package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/Arham1716/imgowner/internal/safeio"
)

// Result is the top-level Trivy JSON output for an image scan.
type Result struct {
	SchemaVersion int            `json:"SchemaVersion"`
	ArtifactName  string         `json:"ArtifactName"`
	Metadata      Metadata       `json:"Metadata"`
	Results       []TargetResult `json:"Results"`
}

type Metadata struct {
	OS          *OS          `json:"OS,omitempty"`
	ImageConfig *ImageConfig `json:"ImageConfig,omitempty"`
}

type OS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type ImageConfig struct {
	RootFS RootFS `json:"rootfs"`
}

type RootFS struct {
	DiffIDs []string `json:"diff_ids"`
}

// TargetResult is one entry in the Trivy Results array (one per OS/lang target).
type TargetResult struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities,omitempty"`
}

// Vulnerability is a single CVE finding from Trivy.
type Vulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Layer            Layer  `json:"Layer"`
}

// Layer identifies which image layer a vulnerability came from.
type Layer struct {
	DiffID string `json:"DiffID"`
	Digest string `json:"Digest,omitempty"`
}

// Runner executes Trivy scans and manages the digest cache.
type Runner struct {
	TrivyVersion string
	Platform     string
	Timeout      time.Duration // per-scan ceiling; zero means no limit
}

// Scan runs Trivy against imageRef (must be digest-pinned) and returns the
// parsed result. Uses the digest cache; skips Trivy if a valid cache entry
// exists (DQ-1). imageRef must be in the form name@sha256:... .
func (r *Runner) Scan(ctx context.Context, imageRef, digest string) (*Result, error) {
	// A cached result is only reused for the same Trivy version and the same
	// vulnerability DB; anything else could hide CVEs published since.
	stamp, err := DBStamp(ctx)
	if err != nil {
		warnOnce("scan cache disabled: %v", err)
	}
	cached, err := ReadCache(digest, r.TrivyVersion, stamp)
	if err != nil {
		warnOnce("scan cache disabled: %v", err)
	}
	if cached != nil {
		var res Result
		if err := json.Unmarshal(cached, &res); err == nil {
			return &res, nil
		}
	}

	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}

	// Run Trivy. --scanners vuln is unconditional (FR-02).
	args := []string{
		"image",
		"--format", "json",
		"--scanners", "vuln",
		"--platform", r.Platform,
		"--quiet",
		imageRef,
	}
	cmd := exec.CommandContext(ctx, "trivy", args...)
	raw, err := safeio.Output(cmd, safeio.MaxTrivyReport, "trivy report")
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("imgowner: trivy scan for %s timed out after %s", imageRef, r.Timeout)
		}
		// Trivy writes diagnostics to stderr; surface them instead of a bare exit code.
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("imgowner: trivy scan failed for %s: %s", imageRef, trimStderr(ee.Stderr))
		}
		return nil, fmt.Errorf("imgowner: trivy scan failed for %s: %w", imageRef, err)
	}

	// Trivy may have refreshed its DB during this scan, so key the entry on
	// the DB the scan actually used. A failed write costs the next run a
	// rescan, never correctness, so it warns rather than fails.
	if after, err := DBStamp(ctx); err == nil {
		if err := WriteCache(digest, r.TrivyVersion, after, raw); err != nil {
			warnOnce("scan result not cached: %v", err)
		}
	}

	var res Result
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("imgowner: parsing trivy output: %w", err)
	}
	return &res, nil
}

// warned dedupes warnings: base-image recommendation scans many candidates
// through one Runner, and the same cache problem should be reported once.
var warned sync.Map

func warnOnce(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if _, seen := warned.LoadOrStore(msg, true); !seen {
		fmt.Fprintln(os.Stderr, "warning: "+msg)
	}
}

// trimStderr caps Trivy's stderr so a runaway log cannot flood the error path.
func trimStderr(b []byte) string {
	const max = 2000
	s := string(b)
	if len(s) > max {
		return s[:max] + "… (truncated)"
	}
	return s
}
