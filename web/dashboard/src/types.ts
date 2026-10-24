// Mirrors the JSON the Go server returns (internal/history, internal/dashboard).

export type Owner = "base" | "added-os" | "app" | "unattributed";
export const OWNERS: readonly Owner[] = ["base", "added-os", "app", "unattributed"];

export interface Summary {
  id: string;
  timestamp: string;
  command: "attribute" | "ci" | "pins-check";
  image: string;
  repository: string;
  digest?: string;
  base_ref?: string;
  dockerfile?: string;
  counts: Record<string, number>;
  severities?: Record<string, number>;
  pin_statuses?: Record<string, number>;
}

export interface Finding {
  cve: string;
  severity: string;
  package: string;
  installed_version: string;
  fixed_version: string;
  class: string;
  layer_index: number;
  owner: Owner;
  unattributed_reason?: string;
  instruction?: { line: number; text: string };
  confidence: string;
}

export interface Pin {
  stage: string;
  package: string;
  version: string;
  available?: string;
  line: number;
  byte_offset: number;
  manager: string;
  status: string;
  fixes_cves?: string[];
}

export interface Candidate {
  ref: string;
  tag: string;
  digest?: string;
  cves_removed: number;
  cves_remaining: number;
  failed: boolean;
  fail_reason?: string;
}

export interface ScanRecord {
  summary: Summary;
  findings: Finding[] | null;
  pins?: Pin[];
  base_candidates?: Candidate[];
}
