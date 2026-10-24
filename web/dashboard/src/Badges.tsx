import type { CSSProperties } from "react";

// Severity and pin state ride the fixed status palette, always with a shape
// and the word beside the colour (never colour alone).
const SEVERITY: Record<string, { color: string; shape: string }> = {
  CRITICAL: { color: "var(--critical)", shape: "x" },
  HIGH: { color: "var(--serious)", shape: "tri" },
  MEDIUM: { color: "var(--warning)", shape: "sq" },
  LOW: { color: "var(--ink-3)", shape: "" },
  UNKNOWN: { color: "var(--ink-3)", shape: "" },
};

export function SeverityBadge({ severity }: { severity: string }) {
  const s = SEVERITY[severity.toUpperCase()] ?? SEVERITY["UNKNOWN"]!;
  return (
    <span className={`badge ${s.shape}`} style={{ "--b": s.color } as CSSProperties}>
      {severity || "UNKNOWN"}
    </span>
  );
}

const PIN: Record<string, { color: string; shape: string; label: string }> = {
  current: { color: "var(--good)", shape: "", label: "up to date" },
  "update-available": { color: "var(--warning)", shape: "tri", label: "update available" },
  "fixes-CVE(s)": { color: "var(--serious)", shape: "tri", label: "update fixes CVEs" },
  unavailable: { color: "var(--critical)", shape: "x", label: "unavailable" },
  unknown: { color: "var(--ink-3)", shape: "sq", label: "unknown" },
  variable: { color: "var(--ink-3)", shape: "sq", label: "variable" },
  unsupported: { color: "var(--ink-3)", shape: "sq", label: "unsupported" },
};

export function PinBadge({ status }: { status: string }) {
  const s = PIN[status] ?? { color: "var(--ink-3)", shape: "sq", label: status };
  return (
    <span className={`badge ${s.shape}`} style={{ "--b": s.color } as CSSProperties}>
      {s.label}
    </span>
  );
}

export const OWNER_VAR: Record<string, string> = {
  base: "--owner-base",
  "added-os": "--owner-added-os",
  app: "--owner-app",
  unattributed: "--owner-unattributed",
};

export const OWNER_LABEL: Record<string, string> = {
  base: "Base image",
  "added-os": "Added OS packages",
  app: "App libraries",
  unattributed: "Unattributed",
};

export function OwnerDot({ owner }: { owner: string }) {
  return <span className="dot" style={{ "--c": `var(${OWNER_VAR[owner] ?? "--ink-3"})` } as CSSProperties} aria-hidden="true" />;
}

export const SEV_COLOR: Record<string, string> = {
  CRITICAL: "var(--critical)",
  HIGH: "var(--serious)",
  MEDIUM: "var(--warning)",
  LOW: "var(--sev-low)",
  UNKNOWN: "var(--sev-unknown)",
};
