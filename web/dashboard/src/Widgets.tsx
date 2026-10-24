import type { CSSProperties, ReactNode } from "react";

export interface Seg {
  label: string;
  value: number;
  color: string; // a CSS colour or var(...)
}

// A horizontal stacked bar: the form for part-to-whole. 2px surface gaps
// between segments, rounded ends, and every value labelled below it, so
// identity never depends on colour alone.
export function StackedBar({ title, segs, thin }: { title?: string; segs: Seg[]; thin?: boolean }) {
  const total = segs.reduce((a, s) => a + s.value, 0);
  const shown = segs.filter((s) => s.value > 0);
  return (
    <div>
      {title && <div className="barlabel">{title}</div>}
      {total === 0 ? (
        <div className="muted">No findings</div>
      ) : (
        <>
          <div className={`stack${thin ? " thin" : ""}`} role="img" aria-label={`${title ?? "Breakdown"}: ${shown.map((s) => `${s.label} ${s.value}`).join(", ")}`}>
            {shown.map((s) => (
              <span key={s.label} title={`${s.label}: ${s.value}`} style={{ "--c": s.color, "--v": s.value } as CSSProperties} />
            ))}
          </div>
          {!thin && (
            <div className="stackkey">
              {shown.map((s) => (
                <span key={s.label}>
                  <i className="sq" style={{ "--c": s.color } as CSSProperties} />
                  {s.label} <b>{s.value}</b> <span className="pc">{Math.round((s.value * 100) / total)}%</span>
                </span>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// 12-point sparkline: the history in the de-emphasis grey, the current
// (latest) point in the series colour.
export function Spark({ values, color }: { values: number[]; color: string }) {
  const v = values.slice(-12);
  if (v.length < 2) return <div className="spark" style={{ height: 26 }} />;
  const w = 132;
  const h = 26;
  const max = Math.max(...v, 1);
  const min = Math.min(...v, 0);
  const span = max - min || 1;
  const pts = v.map((n, i) => [(i * (w - 6)) / (v.length - 1) + 3, h - 4 - ((n - min) * (h - 8)) / span] as const);
  const last = pts[pts.length - 1]!;
  return (
    <svg className="spark" width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Last ${v.length} scans: ${v.join(", ")}`}>
      <polyline points={pts.map((p) => p.join(",")).join(" ")} fill="none" stroke="var(--ink-3)" strokeWidth="1.6" strokeLinejoin="round" strokeLinecap="round" opacity="0.7" />
      <circle cx={last[0]} cy={last[1]} r="3.4" fill={color} stroke="var(--surface)" strokeWidth="2" />
    </svg>
  );
}

// Change against a named period. Colour = direction x whether up is good, and
// the arrow + words carry it too. For findings, fewer is better.
export function Delta({ now, before, label }: { now: number; before: number | undefined; label: string }) {
  const title = "Change since the previous scan of this repository";
  if (before === undefined) return <span className="delta flat" title={title}>first scan</span>;
  const d = now - before;
  if (d === 0) return <span className="delta flat" title={title}>– no change {label}</span>;
  const good = d < 0;
  return (
    <span className={`delta ${good ? "good" : "bad"}`} title={title}>
      {good ? "▼" : "▲"} {Math.abs(d)} {label}
    </span>
  );
}

export function Meter({ pct, color }: { pct: number; color: string }) {
  return (
    <div className="meter" style={{ "--c": color, "--w": `${Math.max(0, Math.min(100, pct))}%` } as CSSProperties} role="meter" aria-valuenow={Math.round(pct)} aria-valuemin={0} aria-valuemax={100}>
      <i />
    </div>
  );
}

export function Card({ title, hint, children }: { title: string; hint?: string; children: ReactNode }) {
  return (
    <section className="card">
      <h2>{title}</h2>
      {hint && <p className="hint">{hint}</p>}
      {children}
    </section>
  );
}
