import * as vscode from "vscode";
import { Candidate, Finding, Pin } from "./types";

export interface DocumentResult {
  findings?: Finding[];
  pins?: Pin[];
  candidates?: Candidate[];
  baseRef?: string;
  image?: string;
}

/**
 * Holds the latest scan results per Dockerfile, keyed by document URI.
 * Diagnostics, the sidebar tree, the hover provider and the status bar all
 * read from this one place, so a single CLI run updates every view at once
 * rather than each view tracking its own copy and drifting out of sync.
 */
export class AttributionState {
  private readonly results = new Map<string, DocumentResult>();
  private readonly emitter = new vscode.EventEmitter<vscode.Uri>();

  /** Fires with the document URI whenever that document's results change. */
  readonly onDidChange = this.emitter.event;

  get(uri: vscode.Uri): DocumentResult | undefined {
    return this.results.get(uri.toString());
  }

  set(uri: vscode.Uri, data: Partial<DocumentResult>): void {
    const existing = this.results.get(uri.toString()) ?? {};
    this.results.set(uri.toString(), { ...existing, ...data });
    this.emitter.fire(uri);
  }

  clear(uri: vscode.Uri): void {
    this.results.delete(uri.toString());
    this.emitter.fire(uri);
  }

  /** All documents with at least one result, for the sidebar tree's root. */
  allUris(): vscode.Uri[] {
    return Array.from(this.results.keys()).map((s) => vscode.Uri.parse(s));
  }

  isEmpty(): boolean {
    return this.results.size === 0;
  }
}
