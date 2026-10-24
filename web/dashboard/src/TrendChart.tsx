import { useEffect, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import type { Summary } from "./types";
import { OWNERS } from "./types";
import { OWNER_LABEL, OWNER_VAR } from "./Badges";

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

const FONT = "12px system-ui, -apple-system, sans-serif";

// Line chart of findings per owner over time: one 2px line per owner, a
// crosshair that snaps to the nearest scan, one tooltip listing every owner,
// and direct labels at the line ends (collision-nudged) on top of the legend
// the parent renders.
export function TrendChart({ scans, themeKey }: { scans: Summary[]; themeKey: string }) {
  const host = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = host.current;
    if (!el) return;

    const sorted = [...scans].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
    const xs = sorted.map((s) => Date.parse(s.timestamp) / 1000);
    const data: uPlot.AlignedData = [xs, ...OWNERS.map((o) => sorted.map((s) => s.counts[o] ?? 0))];

    const ink2 = cssVar("--ink-2");
    const ink3 = cssVar("--ink-3");
    const grid = cssVar("--grid");
    const axis = cssVar("--axis");
    const surface = cssVar("--surface");
    const colors = OWNERS.map((o) => cssVar(OWNER_VAR[o] ?? "--ink-3"));
    const showPoints = sorted.length <= 40;

    // Tooltip: textContent only, because labels and values are untrusted data.
    const tip = document.createElement("div");
    tip.className = "tooltip";
    tip.hidden = true;
    const tooltipPlugin: uPlot.Plugin = {
      hooks: {
        init: (u) => {
          u.over.appendChild(tip);
        },
        setCursor: (u) => {
          const idx = u.cursor.idx;
          if (idx == null || u.cursor.left == null || u.cursor.left < 0) {
            tip.hidden = true;
            return;
          }
          const when = document.createElement("div");
          when.className = "when";
          when.textContent = new Date((xs[idx] ?? 0) * 1000).toLocaleString();
          const rows = OWNERS.map((o, i) => {
            const row = document.createElement("div");
            row.className = "row";
            const key = document.createElement("span");
            key.className = "key";
            key.style.setProperty("--c", colors[i] ?? ink3);
            const name = document.createElement("span");
            name.textContent = OWNER_LABEL[o] ?? o;
            const val = document.createElement("b");
            val.textContent = String(sorted[idx]?.counts[o] ?? 0);
            row.append(key, name, val);
            return row;
          });
          tip.replaceChildren(when, ...rows);
          tip.hidden = false;
          const over = u.over.getBoundingClientRect();
          const left = Math.min(u.cursor.left + 14, over.width - tip.offsetWidth - 4);
          const top = Math.min(Math.max(u.cursor.top ?? 0, 0), Math.max(over.height - tip.offsetHeight - 4, 0));
          tip.style.left = `${Math.max(left, 4)}px`;
          tip.style.top = `${top}px`;
        },
      },
    };

    // Direct labels at the right end of each line.
    const labelPlugin: uPlot.Plugin = {
      hooks: {
        draw: (u) => {
          const last = xs.length - 1;
          if (last < 0) return;
          const dpr = devicePixelRatio;
          const items = OWNERS.map((o, i) => ({
            text: OWNER_LABEL[o] ?? o,
            // With canvas=true valToPos is already canvas-absolute (device px).
            y: u.valToPos(data[i + 1]?.[last] ?? 0, "y", true),
          })).sort((a, b) => a.y - b.y);
          const gap = 15 * dpr;
          for (let i = 1; i < items.length; i++) {
            const prev = items[i - 1];
            const cur = items[i];
            if (prev && cur && cur.y - prev.y < gap) cur.y = prev.y + gap;
          }
          const ctx = u.ctx;
          ctx.save();
          ctx.font = `${12 * dpr}px system-ui, sans-serif`;
          ctx.textBaseline = "middle";
          ctx.textAlign = "left"; // uPlot leaves the axes' centre alignment set on the shared context
          ctx.fillStyle = ink2; // text wears the text token; the line carries the colour
          const x = u.valToPos(xs[last] ?? 0, "x", true) + 10 * dpr;
          for (const it of items) ctx.fillText(it.text, x, it.y);
          ctx.restore();
        },
      },
    };

    const opts: uPlot.Options = {
      width: Math.max(el.clientWidth, 320),
      height: 300,
      padding: [12, 150, 0, 0],
      legend: { show: false },
      // Vertical crosshair only: readers aim at a date, not at a value.
      cursor: { y: false, points: { size: 9, width: 2, fill: surface }, drag: { x: false, y: false } },
      plugins: [tooltipPlugin, labelPlugin],
      scales: { x: { time: true }, y: { range: (_u, _min, max) => [0, Math.max(max * 1.1, 5)] } },
      axes: [
        { stroke: ink3, grid: { stroke: grid, width: 1 }, ticks: { stroke: axis, width: 1 }, font: FONT },
        { stroke: ink3, grid: { stroke: grid, width: 1 }, ticks: { show: false }, font: FONT, size: 48 },
      ],
      series: [
        {},
        ...OWNERS.map((o, i) => ({
          label: OWNER_LABEL[o] ?? o,
          stroke: colors[i] ?? ink3,
          width: 2,
          points: showPoints ? { show: true, size: 8, width: 2, fill: surface } : { show: false },
        })),
      ],
    };

    const plot = new uPlot(opts, data, el);
    const ro = new ResizeObserver(() => plot.setSize({ width: Math.max(el.clientWidth, 320), height: 300 }));
    ro.observe(el);
    return () => {
      ro.disconnect();
      plot.destroy();
    };
  }, [scans, themeKey]);

  return <div ref={host} className="chart-wrap" role="img" aria-label="Findings per owner over time; the same numbers are in the table below" />;
}
