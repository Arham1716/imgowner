package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Result is the top-level Trivy JSON output for an image scan.
type Result struct {
	SchemaVersion int             `json:"SchemaVersion"`
	ArtifactName  string          `json:"ArtifactName"`
	Metadata      Metadata        `json:"Metadata"`
	Results       []TargetResult  `json:"Results"`
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
	DiffID  string `json:"DiffID"`
	Digest  string `json:"Digest,omitempty"`
}

// Runner executes Trivy scans and manages the digest cache.
type Runner struct {
	TrivyVersion string
	Platform     string
}

// Scan runs Trivy against imageRef (must be digest-pinned) and returns the
// parsed result. Uses the digest cache; skips Trivy if a valid cache entry
// exists (DQ-1). imageRef must be in the form name@sha256:... .
func (r *Runner) Scan(ctx context.Context, imageRef, digest string) (*Result, error) {
	// Check cache first.
	if cached, err := ReadCache(digest, r.TrivyVersion); err == nil && cached != nil {
		var res Result
		if err := json.Unmarshal(cached, &res); err == nil {
			return &res, nil
		}
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
	raw, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("imgowner: trivy scan failed for %s: %w", imageRef, err)
	}

	// Persist to cache.
	_ = WriteCache(digest, r.TrivyVersion, raw)

	var res Result
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("imgowner: parsing trivy output: %w", err)
	}
	return &res, nil
}
