// Enforces the dashboard's dependency budget (NFR-19) and supply-chain posture
// (NFR-15): at most five direct runtime dependencies, and every dependency --
// runtime or dev -- pinned to an exact version, so a rebuild never silently
// pulls a different release than the one reviewed.
//
// Usage: node check-dashboard-deps.mjs <path/to/package.json>
import { readFileSync } from "node:fs";

const MAX_RUNTIME = 5;
const EXACT = /^\d+\.\d+\.\d+$/;

const pkg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const runtime = Object.entries(pkg.dependencies ?? {});
const dev = Object.entries(pkg.devDependencies ?? {});
let failed = false;

if (runtime.length > MAX_RUNTIME) {
  console.error(
    `::error::${process.argv[2]}: ${runtime.length} direct runtime dependencies (${runtime.map(([n]) => n).join(", ")}); ` +
      `the budget is ${MAX_RUNTIME} (NFR-19). Justify any addition in the PR and raise MAX_RUNTIME here.`,
  );
  failed = true;
}
for (const [name, range] of [...runtime, ...dev]) {
  if (!EXACT.test(range)) {
    console.error(`::error::${process.argv[2]}: ${name} is "${range}"; pin an exact version (no ^, ~ or ranges)`);
    failed = true;
  }
}
console.log(`${process.argv[2]}: ${runtime.length}/${MAX_RUNTIME} runtime dependencies, ${dev.length} dev, all pinned`);
process.exit(failed ? 1 : 0);
