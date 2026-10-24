export function fmtDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function shortDigest(d?: string): string {
  if (!d) return "";
  const hex = d.startsWith("sha256:") ? d.slice(7) : d;
  return "sha256:" + hex.slice(0, 12);
}

export function sum(counts: Record<string, number> | undefined): number {
  return Object.values(counts ?? {}).reduce((a, b) => a + b, 0);
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
export const severityRank = (s: string): number => {
  const i = SEVERITY_ORDER.indexOf(s.toUpperCase());
  return i < 0 ? SEVERITY_ORDER.length : i;
};
export const SEVERITIES = SEVERITY_ORDER;
