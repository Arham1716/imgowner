import * as vscode from "vscode";
import { Finding, Pin } from "./types";

const SOURCE = "imgowner";

export function severityFromCVE(sev: string): vscode.DiagnosticSeverity {
  switch (sev.toUpperCase()) {
    case "CRITICAL":
    case "HIGH":
      return vscode.DiagnosticSeverity.Error;
    case "MEDIUM":
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

function severityFromPinStatus(status: Pin["status"]): vscode.DiagnosticSeverity | undefined {
  switch (status) {
    case "unavailable":
      return vscode.DiagnosticSeverity.Error;
    case "update-available":
    case "fixes-CVE(s)":
      return vscode.DiagnosticSeverity.Warning;
    case "variable":
    case "unsupported":
      return vscode.DiagnosticSeverity.Information;
    case "unknown":
      return vscode.DiagnosticSeverity.Hint;
    case "current":
      return undefined; // nothing to report
  }
}

/**
 * Builds one diagnostic per CVE finding that carries a Dockerfile line
 * (`instruction`). Findings without one -- base-image CVEs, and anything
 * reported unattributed because the base boundary couldn't be verified --
 * have no single line to anchor to and are surfaced only in the sidebar.
 */
export function buildFindingDiagnostics(
  document: vscode.TextDocument,
  findings: Finding[],
): vscode.Diagnostic[] {
  const diagnostics: vscode.Diagnostic[] = [];

  for (const f of findings) {
    if (!f.instruction) {
      continue;
    }
    const lineIndex = Math.max(0, f.instruction.line - 1);
    if (lineIndex >= document.lineCount) {
      continue; // stale result from before the file changed; don't crash on an out-of-range line
    }
    const line = document.lineAt(lineIndex);

    const diag = new vscode.Diagnostic(
      line.range,
      `${f.cve} (${f.severity}): ${f.package}@${f.installed_version}` +
        (f.fixed_version ? ` -- fixed in ${f.fixed_version}` : "") +
        ` [owner: ${f.owner}]`,
      severityFromCVE(f.severity),
    );
    diag.source = SOURCE;
    diag.code = {
      value: f.cve,
      target: vscode.Uri.parse(`https://nvd.nist.gov/vuln/detail/${f.cve}`),
    };
    diagnostics.push(diag);
  }

  return diagnostics;
}

/**
 * Builds one diagnostic per non-current pin, anchored to the exact version
 * token via its byte offset rather than the whole line -- this is the one
 * place the extension can be more precise than the CVE diagnostics above,
 * because pins.Pin carries a byte_offset and attribution.Finding doesn't.
 */
export function buildPinDiagnostics(
  document: vscode.TextDocument,
  pins: Pin[],
): vscode.Diagnostic[] {
  const diagnostics: vscode.Diagnostic[] = [];
  const text = document.getText();

  for (const p of pins) {
    const severity = severityFromPinStatus(p.status);
    if (severity === undefined) {
      continue;
    }
    if (p.byte_offset < 0 || p.byte_offset + p.version.length > text.length) {
      continue; // stale offset from before the file changed
    }

    const start = document.positionAt(p.byte_offset);
    const end = document.positionAt(p.byte_offset + p.version.length);

    let message = `${p.package} ${p.version}`;
    switch (p.status) {
      case "update-available":
        message += ` -- update available: ${p.available}`;
        break;
      case "fixes-CVE(s)":
        message += ` -- update to ${p.available} fixes ${(p.fixes_cves ?? []).join(", ")}`;
        break;
      case "unavailable":
        message += ` -- this exact version is no longer available in the repo`;
        break;
      case "variable":
        message += ` -- version is an ARG with no default; can't be checked`;
        break;
      case "unsupported":
        message += ` -- package appears to come from a third-party repo; can't be checked`;
        break;
      case "unknown":
        message += ` -- version lookup failed or timed out`;
        break;
    }

    const diag = new vscode.Diagnostic(new vscode.Range(start, end), message, severity);
    diag.source = SOURCE;
    diag.code = p.status;
    diagnostics.push(diag);
  }

  return diagnostics;
}
