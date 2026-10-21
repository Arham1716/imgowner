import * as vscode from "vscode";
import { AttributionState } from "./state";

/**
 * Aggregates every finding and pin on the hovered line into one Markdown
 * hover. Diagnostics already show their own message on hover individually,
 * but when a line has multiple CVEs plus a stale pin, this gives one combined
 * view instead of VS Code stacking several separate diagnostic tooltips.
 */
export class ImgownerHoverProvider implements vscode.HoverProvider {
  constructor(private readonly state: AttributionState) {}

  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
  ): vscode.ProviderResult<vscode.Hover> {
    const result = this.state.get(document.uri);
    if (!result) {
      return undefined;
    }

    const lineNumber1Based = position.line + 1;
    const parts: string[] = [];

    const findingsHere = (result.findings ?? []).filter(
      (f) => f.instruction?.line === lineNumber1Based,
    );
    for (const f of findingsHere) {
      const fixed = f.fixed_version ? ` → fixed in \`${f.fixed_version}\`` : "";
      parts.push(
        `**[${f.cve}](https://nvd.nist.gov/vuln/detail/${f.cve})** (${f.severity}) — ` +
          `\`${f.package}@${f.installed_version}\`${fixed}\n\nOwner: \`${f.owner}\``,
      );
    }

    const offset = document.offsetAt(position);
    const pinsHere = (result.pins ?? []).filter(
      (p) =>
        p.status !== "current" &&
        offset >= p.byte_offset &&
        offset <= p.byte_offset + p.version.length,
    );
    for (const p of pinsHere) {
      let line = `**${p.package}** pinned at \`${p.version}\` — status: \`${p.status}\``;
      if (p.status === "update-available" || p.status === "fixes-CVE(s)") {
        line += `\n\nUpdate available: \`${p.available}\``;
        if (p.fixes_cves?.length) {
          line += ` (fixes ${p.fixes_cves.join(", ")})`;
        }
        line += `\n\n[Update all pins](command:imgowner.updatePins)`;
      }
      parts.push(line);
    }

    if (parts.length === 0) {
      return undefined;
    }

    const md = new vscode.MarkdownString(parts.join("\n\n---\n\n"));
    md.isTrusted = true; // required for the command: link above
    return new vscode.Hover(md);
  }
}
