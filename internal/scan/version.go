package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// trivyVersion holds the parsed Trivy version output.
type trivyVersion struct {
	Version string `json:"Version"`
}

// CheckTrivyVersion verifies Trivy is installed and meets the minimum version
// requirement. Returns a structured error suitable for JSON marshalling (FR-30).
func CheckTrivyVersion(ctx context.Context, minVersion string) error {
	cmd := exec.CommandContext(ctx, "trivy", "version", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return &ErrToolMissing{
			Tool: "trivy",
			Hint: fmt.Sprintf("install trivy ≥ %s from https://github.com/aquasecurity/trivy/releases", minVersion),
		}
	}

	var v trivyVersion
	if err := json.Unmarshal(out, &v); err != nil {
		// Trivy is present but output is unexpected; treat as version unknown.
		return &ErrToolMissing{
			Tool: "trivy",
			Hint: "could not parse trivy version output — reinstall trivy",
		}
	}

	if !versionAtLeast(v.Version, minVersion) {
		return &ErrVersionTooOld{
			Tool:     "trivy",
			Found:    v.Version,
			Required: minVersion,
		}
	}
	return nil
}

// InstalledVersion returns the version string reported by the installed Trivy binary.
func InstalledVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "trivy", "version", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return "", &ErrToolMissing{Tool: "trivy", Hint: "trivy not found"}
	}
	var v trivyVersion
	if err := json.Unmarshal(out, &v); err != nil {
		return "", &ErrToolMissing{Tool: "trivy", Hint: "could not parse trivy version output"}
	}
	return v.Version, nil
}

// versionAtLeast returns true if found >= required (simple semver comparison
// for three-part versions: MAJOR.MINOR.PATCH).
func versionAtLeast(found, required string) bool {
	fp := parseSemver(found)
	rp := parseSemver(required)
	for i := range fp {
		if fp[i] > rp[i] {
			return true
		}
		if fp[i] < rp[i] {
			return false
		}
	}
	return true
}

func parseSemver(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	var out [3]int
	for i, p := range parts {
		if i >= 3 {
			break
		}
		// A non-numeric segment is intentionally left as 0; versionAtLeast
		// still compares the remaining numeric segments correctly.
		_, _ = fmt.Sscanf(p, "%d", &out[i])
	}
	return out
}
