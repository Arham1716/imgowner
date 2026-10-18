package pins

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
