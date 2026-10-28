import type { CSSProperties } from "react";
import { useEffect, useMemo, useState } from "react";
import { getScan } from "./api";
import { OWNER_LABEL, OWNER_VAR, SEV_COLOR } from "./Badges";
import { fmtDate, shortDigest, sum, SEVERITIES } from "./format";
import { TrendChart } from "./TrendChart";
import type { Finding, ScanRecord, Summary } from "./types";
import { OWNERS } from "./types";
import { Card, Delta, Spark, StackedBar } from "./Widgets";

const ownerColor = (o: string) => `var(${OWNER_VAR[o] ?? "--ink-3"})`;
// What a team can act on itself: the layers it added. Base-image findings need
// a different base; unattributed ones need the attribution fixed first.
const OWNED = ["added-os", "app"] as const;

export function Overview({ scans, themeKey }: { scans: Summary[]; themeKey: string }) {
  const desc = useMemo(() => [...scans].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)), [scans]);
  const asc = useMemo(() => [...desc].reverse(), [desc]);
  const latest = desc[0];
  const previous = desc[1];

  // The latest scan's findings drive the package and Dockerfile-line cards.
  const [rec, setRec] = useState<ScanRecord | null>(null);
  useEffect(() => {
    if (!latest) return;
    let live = true;
    getScan(latest.id)
      .then((r) => live && setRec(r))
      .catch(() => live && setRec(null));
    return () => {
      live = false;
    };
  }, [latest?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const findings: Finding[] = rec && latest && rec.summary.id === latest.id ? (rec.findings ?? []) : [];

  const topPackages = useMemo(() => {
    const m = new Map<string, Record<string, number>>();
    for (const f of findings) {
      const e = m.get(f.package) ?? {};
      e[f.owner] = (e[f.owner] ?? 0) + 1;
      m.set(f.package, e);
    }
    return [...m.entries()]
      .map(([name, by]) => ({ name, by, total: Object.values(by).reduce((a, b) => a + b, 0) }))
      .sort((a, b) => b.total - a.total || a.name.localeCompare(b.name))
      .slice(0, 8);
  }, [findings]);

  const topLines = useMemo(() => {
    const m = new Map<number, { line: number; text: string; n: number }>();
    for (const f of findings) {
      if (!f.instruction) continue;
      const e = m.get(f.instruction.line) ?? { line: f.instruction.line, text: f.instruction.text, n: 0 };
      e.n++;
      m.set(f.instruction.line, e);
    }
    return [...m.values()].sort((a, b) => b.n - a.n || a.line - b.line).slice(0, 6);
  }, [findings]);

  if (!latest) {
    return <div className="card empty">No attribution scans in this range for this repository.</div>;
  }

  const owned = OWNED.reduce((a, o) => a + (latest.counts[o] ?? 0), 0);
  const unattributed = latest.counts["unattributed"] ?? 0;
  // When ownership couldn't be determined, "0 findings you own" would read as
  // all-clear; say what actually happened instead.
  const notAttributed = unattributed > 0 && owned === 0 && (latest.counts["base"] ?? 0) === 0;
  const reason = findings.find((f) => f.owner === "unattributed" && f.unattributed_reason)?.unattributed_reason;
  const ownedFixable = findings.filter((f) => (OWNED as readonly string[]).includes(f.owner) && f.fixed_version).length;
  const total = sum(latest.counts);
  const prevOwned = previous ? OWNED.reduce((a, o) => a + (previous.counts[o] ?? 0), 0) : undefined;
  const maxPkg = topPackages[0]?.total ?? 1;
  const maxLine = topLines[0]?.n ?? 1;

  return (
    <>
      <section className={`hero${notAttributed ? " warn" : ""}`}>
        {notAttributed ? (
          <div>
            <div className="eyebrow">Ownership not determined</div>
            <div className="hero-fig">{unattributed}</div>
            <p>
              findings in the latest scan of <b className="mono">{latest.repository}</b> couldn't be attributed to the base
              image or to your Dockerfile, so none of them is counted as yours or the base image's.
            </p>
            {reason && <p className="reason">Why: {reason}</p>}
            <div className="chips">
              <span className="chip">Fix the cause above (usually: pass --base-digest) and scan again</span>
            </div>
          </div>
        ) : (
          <div>
            <div className="eyebrow">Findings you own</div>
            <div className="hero-fig">{owned}</div>
            <p>
              in the latest scan of <b className="mono">{latest.repository}</b>
              {findings.length > 0 && owned > 0 ? ` — ${ownedFixable} of them already have a fix available` : ""}.
            </p>
            <div className="chips">
              <span className="chip">
                <Delta now={owned} before={prevOwned} label="vs previous scan" />
              </span>
              <span className="chip">
                <i className="dot" style={{ "--c": ownerColor("base") } as CSSProperties} />
                {latest.counts["base"] ?? 0} in the base image — fix by changing base
              </span>
              {unattributed > 0 && (
                <span className="chip">
                  <i className="dot" style={{ "--c": ownerColor("unattributed") } as CSSProperties} />
                  {unattributed} not attributed
                </span>
              )}
            </div>
          </div>
        )}
        <div className="bars">
          <StackedBar
            title="Who owns the findings"
            segs={OWNERS.map((o) => ({ label: OWNER_LABEL[o] ?? o, value: latest.counts[o] ?? 0, color: ownerColor(o) }))}
          />
          <StackedBar
            title="How severe they are"
            segs={SEVERITIES.map((s) => ({ label: s[0] + s.slice(1).toLowerCase(), value: latest.severities?.[s] ?? 0, color: SEV_COLOR[s] ?? "var(--ink-3)" }))}
          />
        </div>
      </section>

      <div className="tiles">
        {OWNERS.map((o) => (
          <div className="tile" key={o} style={{ "--c": ownerColor(o) } as CSSProperties}>
            <div className="label">{OWNER_LABEL[o]}</div>
            <div className="row">
              <div className="value">{latest.counts[o] ?? 0}</div>
              <Delta now={latest.counts[o] ?? 0} before={previous ? (previous.counts[o] ?? 0) : undefined} label="" />
            </div>
            <Spark values={asc.map((s) => s.counts[o] ?? 0)} color={ownerColor(o)} />
          </div>
        ))}
        <div className="tile" style={{ "--c": "var(--ink-3)" } as CSSProperties}>
          <div className="label">Total in latest scan</div>
          <div className="row">
            <div className="value">{total}</div>
            <Delta now={total} before={previous ? sum(previous.counts) : undefined} label="" />
          </div>
          <Spark values={asc.map((s) => sum(s.counts))} color="var(--ink-2)" />
        </div>
      </div>

      <Card title="Findings by owner over time" hint="One point per scan. Hover the chart for exact numbers.">
        <ul className="legend">
          {OWNERS.map((o) => (
            <li key={o}>
              <span className="key" style={{ "--c": ownerColor(o) } as CSSProperties} />
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
                {desc.map((s) => (
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
      </Card>

      {findings.length > 0 && (
        <div className="grid2">
          <Card title="Packages with the most findings" hint="Each bar is split by who owns the finding.">
            <div className="rank">
              {topPackages.map((p) => (
                <div className="item" key={p.name}>
                  <span className="name" title={p.name}>
                    {p.name}
                  </span>
                  <div className="stack thin" style={{ width: `${Math.max((p.total * 100) / maxPkg, 6)}%` }}>
                    {OWNERS.filter((o) => p.by[o]).map((o) => (
                      <span key={o} title={`${OWNER_LABEL[o]}: ${p.by[o]}`} style={{ "--c": ownerColor(o), "--v": p.by[o] } as CSSProperties} />
                    ))}
                  </div>
                  <span className="num">{p.total}</span>
                </div>
              ))}
            </div>
          </Card>
          <Card title="Dockerfile lines creating the most findings" hint="The layers you added, traced back to the instruction that made them.">
            {topLines.length === 0 ? (
              <p className="dim">None of this scan's findings come from layers you added.</p>
            ) : (
              <div className="rank">
                {topLines.map((l) => (
                  <div className="item" key={l.line} style={{ gridTemplateColumns: "minmax(110px, 1.2fr) 1fr 42px" }}>
                    <span className="name">
                      <b className="mono">line {l.line}</b>
                      <span className="sub2" title={l.text}>
                        {l.text}
                      </span>
                    </span>
                    <div className="stack thin" style={{ width: `${Math.max((l.n * 100) / maxLine, 6)}%` }}>
                      <span style={{ "--c": ownerColor("added-os"), "--v": 1 } as CSSProperties} />
                    </div>
                    <span className="num">{l.n}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
