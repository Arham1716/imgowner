import { useEffect, useMemo, useState } from "react";
import { getScan } from "./api";
import { OWNER_LABEL, OwnerDot, SeverityBadge } from "./Badges";
import { SEVERITIES, severityRank } from "./format";
import type { Finding, ScanRecord } from "./types";
import { OWNERS } from "./types";

const PAGE = 200;

// Findings of one scan, filterable by owner, severity, package and CVE, each
// row showing the Dockerfile line it is attributed to (FR-35).
export function Findings({ scanId }: { scanId: string | null }) {
  const [rec, setRec] = useState<ScanRecord | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [owner, setOwner] = useState("");
  const [severity, setSeverity] = useState("");
  const [pkg, setPkg] = useState("");
  const [cve, setCve] = useState("");
  const [shown, setShown] = useState(PAGE);

  useEffect(() => {
    if (!scanId) return;
    let live = true;
    // Refetch keeps the previous render in place (dimmed) rather than blanking.
    setErr(null);
    getScan(scanId)
      .then((r) => live && setRec(r))
      .catch((e: Error) => live && setErr(e.message));
    return () => {
      live = false;
    };
  }, [scanId]);

  useEffect(() => setShown(PAGE), [owner, severity, pkg, cve, scanId]);

  const rows = useMemo(() => {
    const all: Finding[] = rec?.findings ?? [];
    const p = pkg.trim().toLowerCase();
    const c = cve.trim().toLowerCase();
    return all
      .filter(
        (f) =>
          (!owner || f.owner === owner) &&
          (!severity || f.severity.toUpperCase() === severity) &&
          (!p || f.package.toLowerCase().includes(p)) &&
          (!c || f.cve.toLowerCase().includes(c)),
      )
      .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.cve.localeCompare(b.cve));
  }, [rec, owner, severity, pkg, cve]);

  if (!scanId) return <div className="card empty">No scan selected.</div>;
  if (err) return <div className="card error">Could not load this scan: {err}</div>;
  if (!rec) return <div className="card empty">Loading…</div>;

  const total = rec.findings?.length ?? 0;
  return (
    <div className="card">
      <div className="filters">
        <label className="field">
          Owner
          <select value={owner} onChange={(e) => setOwner(e.target.value)}>
            <option value="">All owners</option>
            {OWNERS.map((o) => (
              <option key={o} value={o}>
                {OWNER_LABEL[o]}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Severity
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          Package
          <input type="text" value={pkg} onChange={(e) => setPkg(e.target.value)} placeholder="e.g. curl" />
        </label>
        <label className="field">
          CVE
          <input type="text" value={cve} onChange={(e) => setCve(e.target.value)} placeholder="e.g. CVE-2024" />
        </label>
        <div className="dim" role="status" style={{ marginLeft: "auto" }}>
          {rows.length} of {total} finding{total === 1 ? "" : "s"}
        </div>
      </div>

      {total === 0 ? (
        <div className="empty">This scan reported no findings.</div>
      ) : (
        <div className="tablewrap">
          <table>
            <caption className="sr">Findings in the selected scan</caption>
            <thead>
              <tr>
                <th scope="col">CVE</th>
                <th scope="col">Severity</th>
                <th scope="col">Package</th>
                <th scope="col">Installed</th>
                <th scope="col">Fixed in</th>
                <th scope="col">Owner</th>
                <th scope="col">Dockerfile</th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(0, shown).map((f, i) => (
                <tr key={`${f.cve}|${f.package}|${f.installed_version}|${i}`}>
                  <td className="mono">{f.cve}</td>
                  <td>
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td>{f.package}</td>
                  <td className="mono">{f.installed_version}</td>
                  <td className="mono">{f.fixed_version || <span className="muted">no fix yet</span>}</td>
                  <td>
                    <OwnerDot owner={f.owner} />
                    {OWNER_LABEL[f.owner] ?? f.owner}
                    {f.unattributed_reason ? <span className="instr" title={f.unattributed_reason}>{f.unattributed_reason}</span> : null}
                  </td>
                  <td>
                    {f.instruction ? (
                      <>
                        <span className="mono">line {f.instruction.line}</span>
                        <span className="instr" title={f.instruction.text}>
                          {f.instruction.text}
                        </span>
                      </>
                    ) : (
                      <span className="muted">{f.owner === "base" ? "base image" : "—"}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length > shown && (
            <button className="ghost more" onClick={() => setShown((n) => n + PAGE)}>
              Show {Math.min(PAGE, rows.length - shown)} more
            </button>
          )}
        </div>
      )}
    </div>
  );
}
