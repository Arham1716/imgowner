package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Arham1716/imgowner/internal/safeio"
)

// defaultVersionTimeout bounds `trivy version`, applied only when the caller
// set no deadline of its own. It should answer in well under a second; this
// is generous headroom, not an expected wait. Without it, a stalled trivy
// process (seen in practice when it tries to phone home for an update check
// and the network hangs) could block the whole command forever — there was
// no way out short of Ctrl+C.
const defaultVersionTimeout = 15 * time.Second

// withVersionTimeout applies defaultVersionTimeout unless ctx already has a
// deadline, mirroring the rule pins.LookupVersions uses for its own timeout.
func withVersionTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, defaultVersionTimeout)
}

// trivyVersion holds the parsed Trivy version output.
type trivyVersion struct {
	Version         string   `json:"Version"`
	VulnerabilityDB *trivyDB `json:"VulnerabilityDB"`
	JavaDB          *trivyDB `json:"JavaDB"`
}

// trivyDB is one database entry in `trivy version --format json`.
type trivyDB struct {
	UpdatedAt string `json:"UpdatedAt"`
}

// CheckTrivyVersion verifies Trivy is installed and meets the minimum version
// requirement. Returns a structured error suitable for JSON marshalling (FR-30).
func CheckTrivyVersion(ctx context.Context, minVersion string) error {
	ctx, cancel := withVersionTimeout(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, "trivy", "version", "--format", "json")
	out, err := safeio.Output(cmd, safeio.MaxToolOutput, "trivy version output")
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
	ctx, cancel := withVersionTimeout(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, "trivy", "version", "--format", "json")
	out, err := safeio.Output(cmd, safeio.MaxToolOutput, "trivy version output")
	if err != nil {
		return "", &ErrToolMissing{Tool: "trivy", Hint: "trivy not found"}
	}
	var v trivyVersion
	if err := json.Unmarshal(out, &v); err != nil {
		return "", &ErrToolMissing{Tool: "trivy", Hint: "could not parse trivy version output"}
	}
	return v.Version, nil
}

// DBStamp identifies the vulnerability databases Trivy currently has, from
// their UpdatedAt times. It is part of the scan cache key, so a DB update
// invalidates every cached result and newly published CVEs are reported.
// It returns "" when Trivy has no vulnerability DB yet (first run), in which
// case nothing can be proven fresh and the cache is bypassed.
func DBStamp(ctx context.Context) (string, error) {
	ctx, cancel := withVersionTimeout(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, "trivy", "version", "--format", "json")
	out, err := safeio.Output(cmd, safeio.MaxToolOutput, "trivy version output")
	if err != nil {
		return "", fmt.Errorf("reading trivy's database version: %w", err)
	}
	var v trivyVersion
	if err := json.Unmarshal(out, &v); err != nil {
		return "", fmt.Errorf("parsing trivy's database version: %w", err)
	}
	return dbStampOf(v), nil
}

func dbStampOf(v trivyVersion) string {
	if v.VulnerabilityDB == nil || v.VulnerabilityDB.UpdatedAt == "" {
		return ""
	}
	stamp := "vuln=" + v.VulnerabilityDB.UpdatedAt
	if v.JavaDB != nil && v.JavaDB.UpdatedAt != "" {
		stamp += ";java=" + v.JavaDB.UpdatedAt
	}
	return stamp
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
