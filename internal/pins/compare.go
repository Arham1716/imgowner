package pins

import (
	"strconv"
	"strings"
)

// ApplyCVEFixes promotes any pin with Status == StatusUpdateAvailable to
// StatusFixesCVEs when upgrading to Available resolves one or more of the
// attributed CVE IDs in fixedByCVE (FR-16).
//
// fixedByCVE maps package name → set of CVE IDs that a version bump fixes,
// derived from the attribution findings produced in M1.
func ApplyCVEFixes(pins []Pin, fixedByCVE map[string][]string) []Pin {
	for i, p := range pins {
		if p.Status != StatusUpdateAvailable {
			continue
		}
		cves, ok := fixedByCVE[p.Package]
		if !ok || len(cves) == 0 {
			continue
		}
		pins[i].FixesCVEs = cves
		pins[i].Status = StatusFixesCVEs
	}
	return pins
}

// BuildCVEFixMap builds the fixedByCVE map from a list of (package, cveIDs)
// pairs derived from the Trivy scan diff between current and available versions.
// In the M3 flow this is called after LookupVersions; the full cross-check
// against a diff scan is wired in M4.
func BuildCVEFixMap(entries []CVEFixEntry) map[string][]string {
	m := make(map[string][]string, len(entries))
	for _, e := range entries {
		m[e.Package] = append(m[e.Package], e.CVEIDs...)
	}
	return m
}

// CVEFixEntry links a package name to a set of CVEs fixed by its upgrade.
type CVEFixEntry struct {
	Package string
	CVEIDs  []string
}

// VersionAtLeast reports whether version a is at least b, using the ordering
// Debian, Alpine and RPM versions share in practice: an optional numeric
// epoch ("2:") first, then runs of digits compared as numbers and runs of
// other characters compared as text, where '~' sorts before anything
// (1.0~rc1 < 1.0). It decides only whether an available upgrade reaches a
// CVE's fixed version; the authoritative newer/older decision for a pin is
// still made inside the container by the distribution's own tool.
func VersionAtLeast(a, b string) bool {
	return compareVersions(a, b) >= 0
}

func compareVersions(a, b string) int {
	ea, ra := splitEpoch(a)
	eb, rb := splitEpoch(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	for ra != "" || rb != "" {
		// Non-digit run.
		na, ta := leading(ra, false)
		nb, tb := leading(rb, false)
		if c := compareText(na, nb); c != 0 {
			return c
		}
		ra, rb = ta, tb
		// Digit run.
		da, ta := leading(ra, true)
		db, tb := leading(rb, true)
		if c := compareDigits(da, db); c != 0 {
			return c
		}
		ra, rb = ta, tb
	}
	return 0
}

func splitEpoch(v string) (int, string) {
	if i := strings.IndexByte(v, ':'); i > 0 {
		if e, err := strconv.Atoi(v[:i]); err == nil {
			return e, v[i+1:]
		}
	}
	return 0, v
}

func leading(s string, digits bool) (string, string) {
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9') == digits {
		i++
	}
	return s[:i], s[i:]
}

func compareDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// compareText orders non-digit runs character by character, '~' lowest,
// then the end of the run, then letters before other symbols (dpkg's rule).
func compareText(a, b string) int {
	weight := func(s string, i int) int {
		if i >= len(s) {
			return 0
		}
		c := s[i]
		switch {
		case c == '~':
			return -1
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			return int(c)
		default:
			return int(c) + 256
		}
	}
	for i := 0; i < len(a) || i < len(b); i++ {
		if wa, wb := weight(a, i), weight(b, i); wa != wb {
			if wa < wb {
				return -1
			}
			return 1
		}
	}
	return 0
}
