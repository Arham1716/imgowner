// Mirrors internal/attribution/classifier.go, internal/pins/types.go and
// internal/baserec/enumerator.go's JSON tags. Keep in sync by hand: there is
// no shared schema generator between the Go CLI and this extension, so a
// renamed Go field must be updated here too, or parsing silently degrades to
// `undefined` rather than an error (JSON.parse doesn't validate shape).

export type Owner = "base" | "added-os" | "app" | "unattributed";
export type Confidence = "exact" | "fuzzy" | "none";

export interface DockerfileRef {
  line: number;
  text: string;
}

export interface Finding {
  cve: string;
  severity: string;
  package: string;
  installed_version: string;
  fixed_version: string;
  class: string;
  layer_diff_id?: string;
  layer_index: number;
  owner: Owner;
  unattributed_reason?: string;
  instruction?: DockerfileRef;
  confidence: Confidence;
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

export interface JSONReport {
  generated_at: string;
  image: string;
  base_ref: string;
  findings: Finding[];
  base_candidates?: Candidate[];
  pins?: Pin[];
}

export type PinStatus =
  | "current"
  | "update-available"
  | "fixes-CVE(s)"
  | "unavailable"
  | "unknown"
  | "variable"
  | "unsupported";

export interface Pin {
  stage: string;
  package: string;
  version: string;
  available?: string;
  line: number;
  byte_offset: number;
  manager: string;
  status: PinStatus;
  fixes_cves?: string[];
}

/** Shape of the JSON error object imgowner writes to stderr on failure. */
export type CLIErrorPayload = Record<string, string>;
