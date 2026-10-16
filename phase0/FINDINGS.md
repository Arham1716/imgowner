# Phase 0 Findings

Date: 2026-10-15
Trivy version: 0.76.0
Images tested: python:3.12-slim, node:20-slim, nginx:1.25-alpine

---

## Exit criterion: is Layer.DiffID reliably populated?

**YES — 100% populated across all 3 images. Not a single empty DiffID.**

The DiffIDs in Trivy findings exactly match the layer hashes from `docker inspect`.
The layer index mapping (DiffID → position in rootfs.diff_ids) is deterministic and correct.

---

## Results per image

### python:3.12-slim (Debian 13.7 — 4 layers)
| Layer | DiffID prefix | Vulns | Attribution |
|---|---|---|---|
| 0 | sha256:15f1c8eb... | 164 | base (Debian) |
| 2 | sha256:b361fa3b... | 8 | added (Python layer) |
| **Total** | | **172** | |

~95% of CVEs come from the base Debian layer. The app team owns ~5%.

### node:20-slim (Debian 12.13 — 5 layers)
| Layer | DiffID prefix | Vulns | Attribution |
|---|---|---|---|
| 0 | sha256:0da811fd... | 289 | base (Debian) |
| 2 | sha256:631e9f79... | 37 | added (Node layer) |
| **Total** | | **326** | |

~89% from base. Without attribution, a team would waste time on 289 CVEs they can't fix.

### nginx:1.25-alpine (Alpine 3.19.1 — 8 layers)
| Layer | DiffID prefix | Vulns | Attribution |
|---|---|---|---|
| 0 | sha256:d4fc045c... | 24 | base (Alpine) |
| 1 | sha256:75061be6... | 16 | base (Alpine) |
| 7 | sha256:ce495f7b... | 53 | added (nginx layer) |
| **Total** | | **93** | |

Alpine has 2 base layers (confirmed by fetching the Alpine base image separately).
Layer 7 is nginx's own layer — it has the most CVEs (53), meaning nginx's own packages
are the main concern here, not Alpine itself.

---

## Key design confirmations

1. **Layer.DiffID is the right key.** Maps unambiguously to the image's DiffID list.
   No fallback needed for these 3 standard images.

2. **Base layer count cannot be hardcoded.** Must be determined by fetching the base
   image and comparing its DiffID list as a prefix. nginx proves this — 2 base layers,
   not 1.

3. **The "most CVEs are base" claim holds.** python: 95%, node: 89%. nginx is different
   because nginx adds a lot of its own packages. All three confirm the attribution
   split is meaningful.

4. **Alpine works the same way as Debian.** DiffIDs are populated, layer mapping is
   identical. No Alpine-specific handling needed for the core attribution logic.

5. **Trivy version to pin:** 0.76.0 (tested and confirmed). Set as `trivy_min_version`
   in `.imgowner.yaml`.

---

## Gaps / watch items

- **nginx layer[7] has 53 vulns** — more than base. This is because nginx bundles
  many OS packages. Tool must not assume "base = most CVEs"; attribution must be
  computed, not assumed.
- **node layer[2] has 37 vulns** from a lang-pkgs result (npm packages). These would
  correctly be classified `app`, not `added-os`. The Class field in Trivy results
  correctly distinguishes these.
- **Alpine 3.19.1 EOL warning** from Trivy — "no longer supported by the distribution."
  Real-world note: old base images will have this. Tool should surface this warning
  in its report.

---

## Phase 0 verdict

**Exit criteria met. Proceed to /vf-requirements.**

- Layer.DiffID: reliably populated ✅
- Layer mapping: deterministic and correct ✅  
- No existing tool covers both attribution + pin updates ✅ (verified: Renovate has no
  native apt/apk support; Docker Scout is commercial and doesn't open PRs for pins)
