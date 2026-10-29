import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { CLIError, getConfigPath, getImageRef, isConfigPathExplicit, run, runJSON } from "./cliRunner";
import { buildFindingDiagnostics, buildPinDiagnostics } from "./diagnostics";
import { ImgownerHoverProvider } from "./hoverProvider";
import { AttributionState } from "./state";
import { ImgownerStatusBar } from "./statusBar";
import { ImgownerTreeProvider } from "./treeView";
import { JSONReport, Pin } from "./types";

let output: vscode.OutputChannel;
let state: AttributionState;
let diagnostics: vscode.DiagnosticCollection;

// One scan per document+kind at a time: a save during a slow attribution run
// must not start a second Trivy scan of the same image in parallel.
const inFlight = new Set<string>();

export function activate(context: vscode.ExtensionContext): void {
  output = vscode.window.createOutputChannel("imgowner");
  state = new AttributionState();
  diagnostics = vscode.languages.createDiagnosticCollection("imgowner");

  const tree = new ImgownerTreeProvider(state);
  const statusBar = new ImgownerStatusBar(state);

  context.subscriptions.push(
    output,
    diagnostics,
    statusBar,
    vscode.window.registerTreeDataProvider("imgownerFindings", tree),
    vscode.languages.registerHoverProvider({ language: "dockerfile" }, new ImgownerHoverProvider(state)),
    state.onDidChange((uri) => refreshDiagnostics(uri)),

    vscode.commands.registerCommand("imgowner.attributeCurrentFile", () =>
      withActiveDockerfile((doc) => attribute(doc)),
    ),
    vscode.commands.registerCommand("imgowner.checkPins", () =>
      withActiveDockerfile((doc) => checkPins(doc)),
    ),
    vscode.commands.registerCommand("imgowner.updatePins", () =>
      withActiveDockerfile((doc) => updatePins(doc)),
    ),
    vscode.commands.registerCommand("imgowner.setImageRef", () => promptForImageRef()),
    vscode.commands.registerCommand("imgowner.refresh", () => withActiveDockerfile((doc) => refresh(doc))),
    vscode.commands.registerCommand("imgowner.revealLine", revealLine),

    // Pin diagnostics are anchored to byte offsets, which any edit can shift.
    // Drop them as soon as the buffer changes rather than show a squiggle
    // under the wrong text; they are recomputed on save.
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (e.document.languageId === "dockerfile" && e.contentChanges.length > 0 && state.get(e.document.uri)?.pins) {
        state.set(e.document.uri, { pins: undefined });
      }
    }),

    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (doc.languageId !== "dockerfile") {
        return;
      }
      const auto = vscode.workspace.getConfiguration("imgowner", doc.uri).get<boolean>("autoRunOnSave");
      if (auto) {
        void checkPins(doc, { quiet: true });
      }
    }),

    vscode.workspace.onDidCloseTextDocument((doc) => {
      if (doc.languageId === "dockerfile") {
        state.clear(doc.uri);
      }
    }),
  );
}

export function deactivate(): void {
  // Disposables registered on context.subscriptions are cleaned up by VS Code.
}

// ── Commands ─────────────────────────────────────────────────────────────────

async function attribute(doc: vscode.TextDocument): Promise<void> {
  let image = getImageRef(doc.uri);
  if (!image) {
    image = (await promptForImageRef()) ?? "";
    if (!image) {
      return;
    }
  }

  await exclusive(doc, "attribute", "Attributing CVEs (this scans the image and can take a few minutes)…", async () => {
    const { data: report, warnings } = await runJSON<JSONReport>(
      ["attribute", "--image", image, "--dockerfile", doc.uri.fsPath, "--format", "json", ...configArgs(doc)],
      cwdFor(doc),
      output,
    );
    reportWarnings(warnings, false);
    // Go marshals an empty nil slice as JSON null, so a clean image yields
    // "findings": null rather than [].
    const findings = report.findings ?? [];
    state.set(doc.uri, {
      findings,
      candidates: report.base_candidates,
      baseRef: report.base_ref,
      image: report.image,
    });

    const yours = findings.filter((f) => f.owner === "added-os" || f.owner === "app").length;
    const unattributed = findings.filter((f) => f.owner === "unattributed").length;
    let msg = `imgowner: ${findings.length} CVE(s) — ${yours} yours, ${findings.length - yours - unattributed} base`;
    if (unattributed > 0) {
      msg += `, ${unattributed} unattributed`;
    }
    void vscode.window.showInformationMessage(msg);
  });
}

async function checkPins(doc: vscode.TextDocument, opts: { quiet?: boolean } = {}): Promise<void> {
  await exclusive(
    doc,
    "pins",
    "Checking pinned package versions…",
    async () => {
      const { data, warnings } = await runJSON<Pin[] | null>(
        ["pins", "check", "--dockerfile", doc.uri.fsPath, "--format", "json", ...configArgs(doc)],
        cwdFor(doc),
        output,
      );
      const pins = data ?? [];
      state.set(doc.uri, { pins });
      reportWarnings(warnings, opts.quiet ?? false);
      if (!opts.quiet) {
        const stale = pins.filter((p) => p.status !== "current" && p.status !== "unknown").length;
        void vscode.window.showInformationMessage(`imgowner: ${pins.length} pinned package(s), ${stale} need attention`);
      }
    },
    opts.quiet,
  );
}

async function updatePins(doc: vscode.TextDocument): Promise<void> {
  // The CLI rewrites the file on disk; unsaved editor changes would conflict
  // with that write, so require a clean buffer first.
  if (doc.isDirty) {
    const choice = await vscode.window.showWarningMessage(
      "Save the Dockerfile before updating pins? imgowner edits the file on disk.",
      "Save and Update",
      "Cancel",
    );
    if (choice !== "Save and Update" || !(await doc.save())) {
      return;
    }
  }

  await exclusive(doc, "pins", "Updating pinned package versions…", async () => {
    const { stdout, warnings } = await run(
      ["pins", "update", "--dockerfile", doc.uri.fsPath, ...configArgs(doc)],
      cwdFor(doc),
      output,
    );
    reportWarnings(warnings, false);
    void vscode.window.showInformationMessage(`imgowner: ${stdout.trim() || "pins updated"}`);
  });

  // Re-check against the rewritten file so diagnostics reflect the new versions.
  await checkPins(doc, { quiet: true });
}

async function refresh(doc: vscode.TextDocument): Promise<void> {
  await checkPins(doc, { quiet: true });
  if (state.get(doc.uri)?.findings && getImageRef(doc.uri)) {
    await attribute(doc);
  }
}

async function promptForImageRef(): Promise<string | undefined> {
  const resource = vscode.window.activeTextEditor?.document.uri;
  const current = getImageRef(resource);
  const value = await vscode.window.showInputBox({
    title: "imgowner: image to scan",
    prompt: "The image built from this Dockerfile, e.g. myapp:latest or registry.example.com/team/app:1.4.2",
    value: current,
    ignoreFocusOut: true,
    validateInput: (v) => (v.trim() && /\s/.test(v.trim()) ? "Image references cannot contain spaces" : undefined),
  });
  if (value === undefined || !value.trim()) {
    return undefined;
  }

  const target = vscode.workspace.workspaceFolders?.length
    ? vscode.ConfigurationTarget.Workspace
    : vscode.ConfigurationTarget.Global;
  await vscode.workspace.getConfiguration("imgowner", resource).update("image", value.trim(), target);
  return value.trim();
}

async function revealLine(uri: vscode.Uri, line: number): Promise<void> {
  const doc = await vscode.workspace.openTextDocument(uri);
  const editor = await vscode.window.showTextDocument(doc);
  const pos = new vscode.Position(Math.max(0, line - 1), 0);
  editor.selection = new vscode.Selection(pos, pos);
  editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Surfaces CLI warnings from a run that still succeeded but whose results are
 * degraded -- e.g. every pin "unknown" because Docker isn't running. Without
 * this the only trace would be in the Output panel, which nobody opens after
 * a command that appeared to work.
 */
function reportWarnings(warnings: string[], quiet: boolean): void {
  if (warnings.length === 0) {
    return;
  }
  const summary = warnings.length === 1 ? warnings[0] : `${warnings[0]} (+${warnings.length - 1} more)`;
  if (quiet) {
    vscode.window.setStatusBarMessage(`$(warning) imgowner: ${summary}`, 8000);
    return;
  }
  void vscode.window.showWarningMessage(`imgowner: ${summary}`, "Show Output").then((choice) => {
    if (choice === "Show Output") {
      output.show(true);
    }
  });
}

function refreshDiagnostics(uri: vscode.Uri): void {
  const doc = vscode.workspace.textDocuments.find((d) => d.uri.toString() === uri.toString());
  const result = state.get(uri);
  if (!doc || !result) {
    diagnostics.delete(uri);
    return;
  }
  diagnostics.set(uri, [
    ...buildFindingDiagnostics(doc, result.findings ?? []),
    ...buildPinDiagnostics(doc, result.pins ?? []),
  ]);
}

async function withActiveDockerfile(fn: (doc: vscode.TextDocument) => Promise<void>): Promise<void> {
  const doc = vscode.window.activeTextEditor?.document;
  if (!doc || doc.languageId !== "dockerfile") {
    void vscode.window.showWarningMessage("imgowner: open a Dockerfile first.");
    return;
  }
  await fn(doc);
}

/**
 * Runs `task` with a progress indicator, skipping it if the same kind of scan
 * is already running for this document, and turning any CLIError into a
 * user-facing message with a shortcut to the Output panel.
 */
async function exclusive(
  doc: vscode.TextDocument,
  kind: string,
  title: string,
  task: () => Promise<void>,
  quiet = false,
): Promise<void> {
  const key = `${kind}:${doc.uri.toString()}`;
  if (inFlight.has(key)) {
    if (!quiet) {
      void vscode.window.showInformationMessage("imgowner: a scan is already running for this file.");
    }
    return;
  }
  inFlight.add(key);
  try {
    await vscode.window.withProgress(
      {
        location: quiet ? vscode.ProgressLocation.Window : vscode.ProgressLocation.Notification,
        title: `imgowner: ${title}`,
      },
      task,
    );
  } catch (err) {
    const message = err instanceof CLIError ? err.message : String(err);
    output.appendLine(`error: ${message}`);
    if (quiet) {
      // Background runs (on save) report in the status bar only; a modal-style
      // popup on every Ctrl+S while Docker is stopped would be unbearable.
      vscode.window.setStatusBarMessage(`$(error) imgowner: ${message}`, 8000);
      return;
    }
    const choice = await vscode.window.showErrorMessage(`imgowner: ${message}`, "Show Output");
    if (choice === "Show Output") {
      output.show(true);
    }
  } finally {
    inFlight.delete(key);
  }
}

function cwdFor(doc: vscode.TextDocument): string {
  return vscode.workspace.getWorkspaceFolder(doc.uri)?.uri.fsPath ?? path.dirname(doc.uri.fsPath);
}

/**
 * imgowner requires an explicitly-named --config to exist (so a typo'd path
 * isn't silently ignored), but the setting's own default (".imgowner.yaml")
 * is the common case where no config file is committed at all -- passing it
 * unconditionally would fail every such workspace. So: an explicitly-set
 * imgowner.configPath is always passed, letting imgowner error loudly if
 * it's missing (the same "don't silently ignore a typo" guarantee the CLI
 * gives); the unconfigured default is only passed when the file actually
 * exists, so imgowner's built-in defaults apply otherwise -- exactly as
 * running the CLI with no --config flag does.
 */
function configArgs(doc: vscode.TextDocument): string[] {
  const configured = getConfigPath(doc.uri);
  const resolved = path.isAbsolute(configured) ? configured : path.join(cwdFor(doc), configured);
  if (isConfigPathExplicit(doc.uri) || fs.existsSync(resolved)) {
    return ["--config", resolved];
  }
  return [];
}
