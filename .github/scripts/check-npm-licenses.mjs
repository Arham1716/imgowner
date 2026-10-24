// Fails if any package in an npm lockfile (direct or transitive, dev or not)
// carries a GPL, AGPL, LGPL or SSPL licence (FR-45), or a licence field that
// isn't an SPDX expression unless that exact package has been reviewed and
// listed in .github/license-exceptions.json.
//
// No dependencies: reads the lockfile v3 "packages" map, which records each
// package's declared licence.
//
// Usage: node check-npm-licenses.mjs <path/to/package-lock.json>...
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const BLOCKED = /\b(A?GPL|LGPL|SSPL)\b|GNU (Affero |Lesser )?General Public/i;
// Plain SPDX ids and simple AND/OR/WITH expressions, optionally parenthesised.
const SPDX = /^\(?[A-Za-z0-9.+-]+( (AND|OR|WITH) [A-Za-z0-9.+-]+)*\)?$/;

const here = dirname(fileURLToPath(import.meta.url));
const exceptions = JSON.parse(readFileSync(join(here, "..", "license-exceptions.json"), "utf8")).npm;

let failed = false;
for (const lockPath of process.argv.slice(2)) {
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  if (lock.lockfileVersion < 2 || !lock.packages) {
    console.error(`${lockPath}: lockfile v2+ required (found v${lock.lockfileVersion})`);
    failed = true;
    continue;
  }
  let checked = 0;
  for (const [path, pkg] of Object.entries(lock.packages)) {
    if (path === "") continue; // the project itself
    checked++;
    const name = path.replace(/^.*node_modules\//, "");
    const license = typeof pkg.license === "string" ? pkg.license : "";

    if (BLOCKED.test(license)) {
      console.error(`::error::${lockPath}: ${name}@${pkg.version} is ${license} (blocked licence)`);
      failed = true;
    } else if (!SPDX.test(license)) {
      const reviewed = exceptions[name];
      if (!reviewed) {
        console.error(
          `::error::${lockPath}: ${name}@${pkg.version} has licence "${license || "(none)"}"; ` +
            "review it and add it to .github/license-exceptions.json with a reason",
        );
        failed = true;
      }
    }
  }
  console.log(`${lockPath}: checked ${checked} packages`);
}
process.exit(failed ? 1 : 0);
