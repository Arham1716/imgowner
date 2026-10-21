import * as path from "path";
import * as vscode from "vscode";
import { AttributionState, DocumentResult } from "./state";
import { Finding, Owner, Pin, PinStatus } from "./types";

type TreeNode =
  | { kind: "documentRoot"; uri: vscode.Uri }
  | { kind: "ownerGroup"; uri: vscode.Uri; owner: Owner; findings: Finding[] }
  | { kind: "pinGroup"; uri: vscode.Uri; status: PinStatus; pins: Pin[] }
  | { kind: "finding"; uri: vscode.Uri; finding: Finding }
  | { kind: "pin"; uri: vscode.Uri; pin: Pin };

const OWNER_ORDER: Owner[] = ["added-os", "app", "unattributed", "base"];
const PIN_STATUS_ORDER: PinStatus[] = [
  "unavailable",
  "fixes-CVE(s)",
  "update-available",
  "variable",
  "unsupported",
  "unknown",
  "current",
];

export class ImgownerTreeProvider implements vscode.TreeDataProvider<TreeNode> {
  private readonly emitter = new vscode.EventEmitter<TreeNode | undefined>();
  readonly onDidChangeTreeData = this.emitter.event;

  constructor(private readonly state: AttributionState) {
    state.onDidChange(() => this.emitter.fire(undefined));
  }

  refresh(): void {
    this.emitter.fire(undefined);
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    switch (element.kind) {
      case "documentRoot": {
        const item = new vscode.TreeItem(
          path.basename(element.uri.fsPath),
          vscode.TreeItemCollapsibleState.Expanded,
        );
        item.resourceUri = element.uri;
        item.iconPath = vscode.ThemeIcon.File;
        return item;
      }
      case "ownerGroup": {
        const item = new vscode.TreeItem(
          `${element.owner} (${element.findings.length})`,
          vscode.TreeItemCollapsibleState.Collapsed,
        );
        item.iconPath = new vscode.ThemeIcon(
          element.owner === "base" ? "circle-slash" : "warning",
        );
        return item;
      }
      case "pinGroup": {
        const item = new vscode.TreeItem(
          `${element.status} (${element.pins.length})`,
          vscode.TreeItemCollapsibleState.Collapsed,
        );
        item.iconPath = new vscode.ThemeIcon("package");
        return item;
      }
      case "finding": {
        const f = element.finding;
        const item = new vscode.TreeItem(`${f.cve}  ${f.package}@${f.installed_version}`);
        item.description = f.severity;
        item.tooltip = new vscode.MarkdownString(
          `**${f.cve}** (${f.severity})\n\n\`${f.package}@${f.installed_version}\`` +
            (f.fixed_version ? ` → fixed in \`${f.fixed_version}\`` : "") +
            `\n\nOwner: \`${f.owner}\`` +
            (f.unattributed_reason ? `\n\n${f.unattributed_reason}` : ""),
        );
        if (f.instruction) {
          item.command = {
            command: "imgowner.revealLine",
            title: "Go to line",
            arguments: [element.uri, f.instruction.line],
          };
        }
        return item;
      }
      case "pin": {
        const p = element.pin;
        const label = p.available ? `${p.package} ${p.version} → ${p.available}` : `${p.package} ${p.version}`;
        const item = new vscode.TreeItem(label);
        item.description = p.status;
        item.command = {
          command: "imgowner.revealLine",
          title: "Go to line",
          arguments: [element.uri, p.line],
        };
        return item;
      }
    }
  }

  getChildren(element?: TreeNode): TreeNode[] {
    if (!element) {
      return this.state.allUris().map((uri) => ({ kind: "documentRoot", uri }));
    }

    if (element.kind === "documentRoot") {
      const result = this.state.get(element.uri);
      if (!result) {
        return [];
      }
      return [...this.ownerGroups(element.uri, result), ...this.pinGroups(element.uri, result)];
    }

    if (element.kind === "ownerGroup") {
      return element.findings.map((finding) => ({ kind: "finding", uri: element.uri, finding }));
    }

    if (element.kind === "pinGroup") {
      return element.pins.map((pin) => ({ kind: "pin", uri: element.uri, pin }));
    }

    return [];
  }

  private ownerGroups(uri: vscode.Uri, result: DocumentResult): TreeNode[] {
    const findings = result.findings ?? [];
    const nodes: TreeNode[] = [];
    for (const owner of OWNER_ORDER) {
      const matching = findings.filter((f) => f.owner === owner);
      if (matching.length > 0) {
        nodes.push({ kind: "ownerGroup", uri, owner, findings: matching });
      }
    }
    return nodes;
  }

  private pinGroups(uri: vscode.Uri, result: DocumentResult): TreeNode[] {
    const pins = result.pins ?? [];
    const nodes: TreeNode[] = [];
    for (const status of PIN_STATUS_ORDER) {
      if (status === "current") {
        continue; // current pins are not actionable; omit to keep the tree focused
      }
      const matching = pins.filter((p) => p.status === status);
      if (matching.length > 0) {
        nodes.push({ kind: "pinGroup", uri, status, pins: matching });
      }
    }
    return nodes;
  }
}
