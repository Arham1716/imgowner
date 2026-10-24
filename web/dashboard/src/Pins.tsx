import { useEffect, useState } from "react";
import { latestPins } from "./api";
import type { CSSProperties } from "react";
import { PinBadge } from "./Badges";
import { Card, Meter } from "./Widgets";
import { fmtDate } from "./format";
import type { Pin, ScanRecord } from "./types";

// Pinned packages from the latest `pins check` of each Dockerfile (FR-36).
export function Pins() {
  const [records, setRecords] = useState<(ScanRecord & { pins: Pin[] })[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [which, setWhich] = useState(0);

  useEffect(() => {
    let live = true;
    latestPins()
      .then((r) => live && setRecords(r.records))
      .catch((e: Error) => live && setErr(e.message));
    return () => {
      live = false;
    };
  }, []);

  if (err) return <div className="card error">Could not load pins: {err}</div>;
  if (!records) return <div className="card empty">Loading…</div>;
  if (records.length === 0) {
    return (
      <div className="card empty">
        No pin checks recorded yet. Run <span className="mono">imgowner pins check --dockerfile Dockerfile</span>.
      </div>
    );
  }

  const rec = records[Math.min(which, records.length - 1)];
  if (!rec) return null;
  const pins = rec.pins ?? [];
  const count = (s: string) => pins.filter((p) => p.status === s).length;
  const current = count("current");
  const behind = count("update-available") + count("fixes-CVE(s)");
  const broken = count("unavailable");
  // Health = share of pins that are exactly up to date; the meter colour carries
  // the state (good -> warning -> critical) and the track is a lighter step of it.
  const health = pins.length ? (current * 100) / pins.length : 100;
  const healthColor = broken > 0 ? "var(--critical)" : behind > 0 ? "var(--warning)" : "var(--good)";

  return (
    <Card title="Pinned packages" hint="Each exact-pinned OS package against the newest version the base image's repositories offer.">
      {pins.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div className="chips" style={{ marginBottom: 10 }}>
            <span className="chip"><i className="dot" style={{ "--c": "var(--good)" } as CSSProperties} /> Up to date <b>{current}</b></span>
            <span className="chip"><i className="dot" style={{ "--c": "var(--warning)" } as CSSProperties} /> Update available <b>{behind}</b></span>
            <span className="chip"><i className="dot" style={{ "--c": "var(--critical)" } as CSSProperties} /> Unavailable <b>{broken}</b></span>
          </div>
          <Meter pct={health} color={healthColor} />
          <p className="dim" style={{ margin: "6px 0 0" }}>{Math.round(health)}% of pins are up to date</p>
        </div>
      )}
      <div className="filters">
        {records.length > 1 && (
          <label className="field">
            Dockerfile
            <select value={which} onChange={(e) => setWhich(Number(e.target.value))}>
              {records.map((r, i) => (
                <option key={r.summary.id} value={i}>
                  {r.summary.dockerfile || r.summary.image}
                </option>
              ))}
            </select>
          </label>
        )}
        <div className="dim">
          Checked {fmtDate(rec.summary.timestamp)}
          {rec.summary.image ? ` against ${rec.summary.image}` : ""}
        </div>
      </div>
      {pins.length === 0 ? (
        <div className="empty">That Dockerfile has no pinned OS packages.</div>
      ) : (
        <div className="tablewrap">
          <table>
            <caption className="sr">Pinned packages and their latest available versions</caption>
            <thead>
              <tr>
                <th scope="col">Package</th>
                <th scope="col">Manager</th>
                <th scope="col">Pinned</th>
                <th scope="col">Latest available</th>
                <th scope="col">Status</th>
                <th scope="col" className="num">
                  Line
                </th>
              </tr>
            </thead>
            <tbody>
              {pins.map((p, i) => (
                <tr key={`${p.package}|${p.line}|${i}`}>
                  <td>{p.package}</td>
                  <td>{p.manager}</td>
                  <td className="mono">{p.version}</td>
                  <td className="mono">{p.available || <span className="muted">—</span>}</td>
                  <td>
                    <PinBadge status={p.status} />
                  </td>
                  <td className="num">{p.line}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
