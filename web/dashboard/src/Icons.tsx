// Small inline stroke icons (no icon library: every dependency is supply-chain
// surface, and the dashboard has a budget of five).
const base = { width: 18, height: 18, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": true } as const;

export const IconOverview = () => (
  <svg {...base}>
    <rect x="3" y="3" width="7" height="9" rx="1.5" />
    <rect x="14" y="3" width="7" height="5" rx="1.5" />
    <rect x="14" y="12" width="7" height="9" rx="1.5" />
    <rect x="3" y="16" width="7" height="5" rx="1.5" />
  </svg>
);
export const IconFindings = () => (
  <svg {...base}>
    <path d="M12 3 3 7.5v5c0 4.5 3.8 7.8 9 9 5.2-1.2 9-4.5 9-9v-5L12 3Z" />
    <path d="M12 8v5M12 16.5v.01" />
  </svg>
);
export const IconPins = () => (
  <svg {...base}>
    <path d="M9 4h6l-1 6 3 3H7l3-3-1-6Z" />
    <path d="M12 13v8" />
  </svg>
);
export const IconBase = () => (
  <svg {...base}>
    <path d="m12 3 9 5-9 5-9-5 9-5Z" />
    <path d="m3 13 9 5 9-5" />
    <path d="m3 17.5 9 5 9-5" opacity="0.5" />
  </svg>
);
export const IconSun = () => (
  <svg {...base}>
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
  </svg>
);
export const IconMoon = () => (
  <svg {...base}>
    <path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5Z" />
  </svg>
);
export const IconAuto = () => (
  <svg {...base}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 3v18" />
    <path d="M12 3a9 9 0 0 1 0 18" fill="currentColor" stroke="none" opacity="0.5" />
  </svg>
);

// The brand mark: a stack of image layers.
export function BrandMark() {
  return (
    <svg width="34" height="34" viewBox="0 0 34 34" aria-hidden="true">
      <defs>
        <linearGradient id="bm" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#3987e5" />
          <stop offset="1" stopColor="#184f95" />
        </linearGradient>
      </defs>
      <rect width="34" height="34" rx="9" fill="url(#bm)" />
      <path d="m17 8 9 4.6-9 4.6-9-4.6L17 8Z" fill="#fff" />
      <path d="m8 17.2 9 4.6 9-4.6" stroke="#fff" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round" opacity="0.8" />
      <path d="m8 21.6 9 4.6 9-4.6" stroke="#fff" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round" opacity="0.5" />
    </svg>
  );
}
