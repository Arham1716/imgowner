import type { CSSProperties } from "react";
import { OWNER_LABEL, OWNER_VAR } from "./Badges";
import { fmtDate, shortDigest, sum } from "./format";
import { TrendChart } from "./TrendChart";
import type { Summary } from "./types";
import { OWNERS } from "./types";

// Overview: findings per owner over time for the selected repository (FR-34).
export function Overview({ scans, themeKey }: { scans: Summary[]; themeKey: string }) {
  if (scans.length === 0) {
    return <div className="card empty">No attribution scans in this range for this repository.</div>;
  }
  const latest = scans.reduce((a, b) => (Date.parse(a.timestamp) >= Date.parse(b.timestamp) ? a : b));
  const asc = [...scans].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));

  return (
    <>
      <div className="tiles">
        {OWNERS.map((o) => (
          <div className="tile" key={o}>
            <div className="label">
              <span className="key" style={{ "--c": `var(${OWNER_VAR[o]})` } as CSSProperties} />
              {OWNER_LABEL[o]}
            </div>
            <div className="value">{latest.counts[o] ?? 0}</div>
          </div>
        ))}
        <div className="tile">
          <div className="label">Total in latest scan</div>
          <div className="value">{sum(latest.counts)}</div>
        </div>
      </div>

      <div className="card">
        <h2>Findings by owner over time</h2>
        <ul className="legend">
          {OWNERS.map((o) => (
            <li key={o}>
              <span className="key" style={{ "--c": `var(${OWNER_VAR[o]})` } as CSSProperties} />
              {OWNER_LABEL[o]}
            </li>
          ))}
        </ul>
        <TrendChart scans={scans} themeKey={themeKey} />
        <p className="dim" style={{ margin: "8px 0 0" }}>
          Latest scan {fmtDate(latest.timestamp)} · {scans.length} scan{scans.length === 1 ? "" : "s"} in range
          {latest.digest ? ` · ${shortDigest(latest.digest)}` : ""}
        </p>
        <details className="tableview">
          <summary>Show as table</summary>
          <div className="tablewrap">
            <table>
              <caption className="sr">Findings per owner for each scan</caption>
              <thead>
                <tr>
                  <th scope="col">Scanned</th>
                  <th scope="col">Image</th>
                  {OWNERS.map((o) => (
                    <th scope="col" className="num" key={o}>
                      {OWNER_LABEL[o]}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {asc
                  .slice()
                  .reverse()
                  .map((s) => (
                    <tr key={s.id}>
                      <td>{fmtDate(s.timestamp)}</td>
                      <td className="mono">{s.image}</td>
                      {OWNERS.map((o) => (
                        <td className="num" key={o}>
                          {s.counts[o] ?? 0}
                        </td>
                      ))}
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </details>
      </div>
    </>
  );
}
