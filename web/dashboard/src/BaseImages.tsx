import { useEffect, useMemo, useState } from "react";
import { getScan } from "./api";
import { shortDigest } from "./format";
import type { ScanRecord } from "./types";

// Candidate base-image tags recorded with a scan, fewest remaining CVEs first,
// each with its digest and the CVE-count change against the current base
// (FR-37).
export function BaseImages({ scanId }: { scanId: string | null }) {
  const [rec, setRec] = useState<ScanRecord | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    let live = true;
    setErr(null);
    getScan(scanId)
      .then((r) => live && setRec(r))
      .catch((e: Error) => live && setErr(e.message));
    return () => {
      live = false;
    };
  }, [scanId]);

  const rows = useMemo(
    () =>
      [...(rec?.base_candidates ?? [])].sort(
        (a, b) => Number(a.failed) - Number(b.failed) || a.cves_remaining - b.cves_remaining || a.tag.localeCompare(b.tag),
      ),
    [rec],
  );

  if (!scanId) return <div className="card empty">No scan selected.</div>;
  if (err) return <div className="card error">Could not load this scan: {err}</div>;
  if (!rec) return <div className="card empty">Loading…</div>;
  if (rows.length === 0) {
    return (
      <div className="card empty">
        This scan has no base image recommendations (they need a confidently resolved base and{" "}
        <span className="mono">base_candidates</span> above 0).
      </div>
    );
  }

  return (
    <div className="card">
      <p className="dim" style={{ marginTop: 0 }}>
        Current base: <span className="mono">{rec.summary.base_ref || "unknown"}</span>
      </p>
      <div className="tablewrap">
        <table>
          <caption className="sr">Candidate base image tags</caption>
          <thead>
            <tr>
              <th scope="col">Tag</th>
              <th scope="col">Digest</th>
              <th scope="col" className="num">
                CVEs remaining
              </th>
              <th scope="col" className="num">
                Change vs current base
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.ref || c.tag}>
                <td className="mono">{c.tag}</td>
                <td className="mono">{shortDigest(c.digest) || <span className="muted">—</span>}</td>
                {c.failed ? (
                  <td colSpan={2} className="dim">
                    scan failed{c.fail_reason ? `: ${c.fail_reason}` : ""}
                  </td>
                ) : (
                  <>
                    <td className="num">{c.cves_remaining}</td>
                    <td className="num">
                      {c.cves_removed > 0 ? (
                        <span style={{ color: "var(--good-text)" }}>▼ {c.cves_removed} fewer</span>
                      ) : c.cves_removed < 0 ? (
                        <span>▲ {-c.cves_removed} more</span>
                      ) : (
                        <span className="muted">no change</span>
                      )}
                    </td>
                  </>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
