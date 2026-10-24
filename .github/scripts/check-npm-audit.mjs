// Runs `npm audit` at --audit-level=high and fails unless every HIGH/CRITICAL
// advisory is a reviewed, written exception in .github/audit-exceptions.json
// for this path (NFR-44). Mirrors check-npm-licenses.mjs's exception model:
// a blanket `npm audit || true` would silently accept any future advisory,
// including ones with no such justification.
//
// Usage: node check-npm-audit.mjs <path-containing-package.json>
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const target = process.argv[2];
if (!target) {
  console.error("usage: check-npm-audit.mjs <path>");
  process.exit(2);
}

const here = dirname(fileURLToPath(import.meta.url));
const allExceptions = JSON.parse(readFileSync(join(here, "..", "audit-exceptions.json"), "utf8"));
const exceptions = new Map((allExceptions[target] ?? []).map((e) => [e.ghsa, e]));

let report;
try {
  const out = execFileSync("npm", ["audit", "--audit-level=high", "--json"], {
    cwd: target,
    encoding: "utf8",
    shell: true, // npm is a shell shim (.cmd) on Windows; harmless on Linux
  });
  report = JSON.parse(out);
} catch (err) {
  // npm audit exits non-zero when it finds advisories at/above the level;
  // its JSON report is still on stdout.
  if (!err.stdout) {
    console.error("npm audit produced no output:", err.message);
    process.exit(2);
  }
  report = JSON.parse(err.stdout);
}

let failed = false;
for (const vuln of Object.values(report.vulnerabilities ?? {})) {
  if (vuln.severity !== "high" && vuln.severity !== "critical") continue;
  for (const via of vuln.via) {
    if (typeof via !== "object") continue; // a string entry just names a dependent package
    const ghsa = (via.url ?? "").split("/").pop();
    const exc = exceptions.get(ghsa);
    if (exc) {
      console.log(`${target}: ${ghsa} (${via.name}) accepted -- ${exc.reason}`);
    } else {
      console.error(`::error::${target}: unreviewed ${vuln.severity} advisory ${ghsa} in ${via.name}; ` +
        "fix it or add a reviewed entry to .github/audit-exceptions.json");
      failed = true;
    }
  }
}

process.exit(failed ? 1 : 0);
