import { useEffect, useMemo, useState, type ReactElement } from "react";
import { ApiError, listScans } from "./api";
import { BaseImages } from "./BaseImages";
import { Findings } from "./Findings";
import { fmtDate, sum } from "./format";
import { Overview } from "./Overview";
import { BrandMark, IconAuto, IconBase, IconFindings, IconMoon, IconOverview, IconPins, IconSun } from "./Icons";
import { Pins } from "./Pins";
import type { Summary } from "./types";

type Tab = "overview" | "findings" | "pins" | "base";
const TABS: { id: Tab; label: string; blurb: string; icon: () => ReactElement }[] = [
  { id: "overview", label: "Overview", blurb: "Who owns your CVEs, and how that is trending", icon: IconOverview },
  { id: "findings", label: "Findings", blurb: "Every CVE in a scan, traced to its Dockerfile line", icon: IconFindings },
  { id: "pins", label: "Pins", blurb: "Pinned OS packages against what is available", icon: IconPins },
  { id: "base", label: "Base images", blurb: "Safer base image candidates for this image", icon: IconBase },
];
const RANGES = [7, 30, 90] as const;
type Theme = "auto" | "light" | "dark";

// Theme choice is a per-viewer convenience; storage may be blocked, so every
// access is guarded and the page works without it.
function loadTheme(): Theme {
  try {
    const t = localStorage.getItem("imgowner-theme");
    return t === "light" || t === "dark" ? t : "auto";
  } catch {
    return "auto";
  }
}

function applyTheme(t: Theme) {
  if (t === "auto") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
}

export function App() {
  const [scans, setScans] = useState<Summary[] | null>(null);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [repo, setRepo] = useState("");
  const [days, setDays] = useState<number>(90);
  const [scanId, setScanId] = useState<string | null>(null);
  const [theme, setTheme] = useState<Theme>(loadTheme);
  const [osDark, setOsDark] = useState(() => matchMedia("(prefers-color-scheme: dark)").matches);

  useEffect(() => {
    applyTheme(theme);
    try {
      if (theme === "auto") localStorage.removeItem("imgowner-theme");
      else localStorage.setItem("imgowner-theme", theme);
    } catch {
      /* storage unavailable: the choice just won't persist */
    }
  }, [theme]);

  useEffect(() => {
    const mq = matchMedia("(prefers-color-scheme: dark)");
    const on = () => setOsDark(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);

  // The chart paints with resolved colours, so it must redraw when the
  // effective theme changes.
  const themeKey = theme === "auto" ? (osDark ? "dark" : "light") : theme;

  useEffect(() => {
    let live = true;
    listScans(90)
      .then((r) => live && setScans(r.scans))
      .catch((e: Error) => live && setError(e));
    return () => {
      live = false;
    };
  }, []);

  const repos = useMemo(() => [...new Set((scans ?? []).filter((s) => s.command !== "pins-check").map((s) => s.repository))].sort(), [scans]);
  const activeRepo = repo && repos.includes(repo) ? repo : (repos[0] ?? "");

  const cutoff = Date.now() - days * 86_400_000;
  const attribution = useMemo(
    () => (scans ?? []).filter((s) => s.command !== "pins-check" && s.repository === activeRepo && Date.parse(s.timestamp) >= cutoff),
    [scans, activeRepo, cutoff],
  );

  // Default to the newest scan in view; keep the user's pick while it's still listed.
  const effectiveScanId = attribution.some((s) => s.id === scanId) ? scanId : (attribution[0]?.id ?? null);

  if (error) {
    const expired = error instanceof ApiError && error.status === 401;
    return (
      <div className="app">
        <h1>imgowner dashboard</h1>
        <div className="card error" role="alert">
          {expired
            ? "This session isn't valid. Stop the dashboard and run `imgowner dashboard` again, then open the URL it prints."
            : `Could not load scan history: ${error.message}`}
        </div>
      </div>
    );
  }
  if (!scans) {
    return (
      <div className="app">
        <h1>imgowner dashboard</h1>
        <div className="empty">Loading…</div>
      </div>
    );
  }

  const hasAny = scans.length > 0;
  const current = TABS.find((x) => x.id === tab) ?? TABS[0]!;
  return (
    <div className="shell">
      <aside className="side">
        <div className="brand">
          <BrandMark />
          <div>
            <b>imgowner</b>
            <small>CVE ownership dashboard</small>
          </div>
        </div>
        <nav className="nav" role="tablist" aria-label="Views" aria-orientation="vertical">
          {TABS.map((x) => (
            <button key={x.id} role="tab" aria-selected={tab === x.id} onClick={() => setTab(x.id)}>
              <x.icon />
              {x.label}
            </button>
          ))}
        </nav>
        <div className="side-foot">
          <div className="badge-local">
            <i /> Local and read-only
          </div>
          <div className="themeseg" role="group" aria-label="Colour theme">
            {(["auto", "light", "dark"] as const).map((th) => (
              <button key={th} aria-pressed={theme === th} aria-label={`${th} theme`} title={`${th} theme`} onClick={() => setTheme(th)}>
                {th === "auto" ? <IconAuto /> : th === "light" ? <IconSun /> : <IconMoon />}
              </button>
            ))}
          </div>
        </div>
      </aside>

      <main className="main">
        <div className="topbar">
          <div className="titlebar">
            <h1>{current.label}</h1>
            <p className="sub">{current.blurb}</p>
          </div>
          {hasAny && tab !== "pins" && (
            <div className="filters">
              <label className="field">
                Repository
                <select value={activeRepo} onChange={(e) => setRepo(e.target.value)}>
                  {repos.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </label>
              <div className="field">
                Range
                <div className="seg" role="group" aria-label="Date range">
                  {RANGES.map((d) => (
                    <button key={d} aria-pressed={days === d} onClick={() => setDays(d)}>
                      {d} days
                    </button>
                  ))}
                </div>
              </div>
              {(tab === "findings" || tab === "base") && attribution.length > 0 && (
                <label className="field">
                  Scan
                  <select value={effectiveScanId ?? ""} onChange={(e) => setScanId(e.target.value)}>
                    {attribution.map((s) => (
                      <option key={s.id} value={s.id}>
                        {fmtDate(s.timestamp)} · {sum(s.counts)} findings · {s.image}
                      </option>
                    ))}
                  </select>
                </label>
              )}
            </div>
          )}
        </div>

        {!hasAny ? (
          <div className="card empty">
            <p>No scans recorded yet.</p>
            <p>
              Run <span className="mono">imgowner attribute --image &lt;ref&gt; --dockerfile Dockerfile</span> and refresh this page.
            </p>
          </div>
        ) : (
          <div role="tabpanel">
            {tab === "overview" && <Overview scans={attribution} themeKey={themeKey} />}
            {tab === "findings" && <Findings scanId={effectiveScanId} />}
            {tab === "pins" && <Pins />}
            {tab === "base" && <BaseImages scanId={effectiveScanId} />}
          </div>
        )}
      </main>
    </div>
  );
}
