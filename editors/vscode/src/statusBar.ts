import * as vscode from "vscode";
import { AttributionState } from "./state";

/** Shows the issue count for the active Dockerfile; hidden for other files. */
export class ImgownerStatusBar implements vscode.Disposable {
  private readonly item: vscode.StatusBarItem;
  private readonly subscriptions: vscode.Disposable[] = [];

  constructor(private readonly state: AttributionState) {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.item.command = "workbench.view.extension.imgowner";

    this.subscriptions.push(
      state.onDidChange(() => this.update()),
      vscode.window.onDidChangeActiveTextEditor(() => this.update()),
    );
    this.update();
  }

  update(): void {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.languageId !== "dockerfile") {
      this.item.hide();
      return;
    }

    const result = this.state.get(editor.document.uri);
    if (!result) {
      this.item.text = "$(shield) imgowner: not scanned";
      this.item.tooltip = "Run 'imgowner: Attribute CVEs' or 'imgowner: Check Pinned Package Versions'";
      this.item.show();
      return;
    }

    const findings = result.findings ?? [];
    const yours = findings.filter((f) => f.owner === "added-os" || f.owner === "app").length;
    const base = findings.filter((f) => f.owner === "base").length;
    const unattributed = findings.filter((f) => f.owner === "unattributed").length;
    const stalePins = (result.pins ?? []).filter(
      (p) => p.status === "update-available" || p.status === "fixes-CVE(s)" || p.status === "unavailable",
    ).length;

    const actionable = yours + stalePins;
    this.item.text = `$(${actionable > 0 ? "warning" : "shield"}) imgowner: ${actionable} actionable`;
    this.item.tooltip =
      `Yours (added-os + app): ${yours}\n` +
      `Base image: ${base}\n` +
      `Unattributed: ${unattributed}\n` +
      `Stale pins: ${stalePins}`;
    this.item.show();
  }

  dispose(): void {
    this.item.dispose();
    this.subscriptions.forEach((s) => s.dispose());
  }
}
