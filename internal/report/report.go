package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/baserec"
	"github.com/Arham1716/imgowner/internal/pins"
)

// Request bundles everything needed to write a report.
type Request struct {
	Image      string
	BaseRef    string
	Findings   []attribution.Finding
	Candidates []baserec.Candidate
	Pins       []pins.Pin
	OutputDir  string   // directory to write files into; empty = stdout only
	Formats    []string // "md", "json", "sarif"
}

// WriteToWriter renders only the first format in req.Formats to w.
// Used for SCM PR comment generation (FR-24).
func WriteToWriter(w io.Writer, req Request) error {
	if len(req.Formats) == 0 {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(req.Formats[0])) {
	case "md", "markdown":
		return renderMarkdown(w, req)
	case "json":
		return renderJSON(w, req)
	case "sarif":
		return renderSARIF(w, req)
	}
	return nil
}

// Write produces all requested report formats (FR-21, FR-22, FR-23).
func Write(req Request) error {
	for _, fmt := range req.Formats {
		switch strings.ToLower(strings.TrimSpace(fmt)) {
		case "md", "markdown":
			if err := writeFormat(req, "md", renderMarkdown); err != nil {
				return err
			}
		case "json":
			if err := writeFormat(req, "json", renderJSON); err != nil {
				return err
			}
		case "sarif":
			if err := writeFormat(req, "sarif", renderSARIF); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeFormat(req Request, ext string, render func(io.Writer, Request) error) error {
	if req.OutputDir == "" {
		return render(os.Stdout, req)
	}
	if err := os.MkdirAll(req.OutputDir, 0o755); err != nil {
		return fmt.Errorf("report: mkdir %s: %w", req.OutputDir, err)
	}
	path := filepath.Join(req.OutputDir, "imgowner-report."+ext)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("report: create %s: %w", path, err)
	}
	defer f.Close()
	return render(f, req)
}

// ── Markdown ──────────────────────────────────────────────────────────────────

func renderMarkdown(w io.Writer, req Request) error {
	counts := findingCounts(req.Findings)
	fmt.Fprintf(w, "# imgowner report\n\n")
	fmt.Fprintf(w, "**Image:** `%s`  \n**Base:** `%s`  \n**Generated:** %s\n\n",
		req.Image, req.BaseRef, time.Now().UTC().Format(time.RFC3339))

	fmt.Fprintf(w, "## CVE attribution\n\n")
	fmt.Fprintf(w, "| Owner | Count |\n|---|---|\n")
	fmt.Fprintf(w, "| base | %d |\n", counts[attribution.OwnerBase])
	fmt.Fprintf(w, "| added-os | %d |\n", counts[attribution.OwnerAddedOS])
	fmt.Fprintf(w, "| app | %d |\n", counts[attribution.OwnerApp])
	fmt.Fprintf(w, "| unattributed | %d |\n\n", counts[attribution.OwnerUnattributed])

	if len(req.Findings) > 0 {
		fmt.Fprintf(w, "### Findings\n\n")
		fmt.Fprintf(w, "| CVE | Severity | Package | Version | Owner | Instruction |\n|---|---|---|---|---|---|\n")
		for _, f := range req.Findings {
			instr := ""
			if f.Instruction != nil {
				instr = f.Instruction.Text
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n",
				f.CVE, f.Severity, f.Package, f.InstalledVersion, f.Owner, instr)
		}
		fmt.Fprintf(w, "\n")
	}

	if len(req.Candidates) > 0 {
		fmt.Fprintf(w, "## Base image recommendations\n\n")
		fmt.Fprintf(w, "| Tag | CVEs removed | CVEs remaining |\n|---|---|---|\n")
		for _, c := range req.Candidates {
			if c.Failed {
				fmt.Fprintf(w, "| %s | — | — | *(scan failed: %s)* |\n", c.Tag, c.FailReason)
			} else {
				fmt.Fprintf(w, "| %s | %d | %d |\n", c.Tag, c.CVEsRemoved, c.CVEsRemaining)
			}
		}
		fmt.Fprintf(w, "\n")
	}

	if len(req.Pins) > 0 {
		fmt.Fprintf(w, "## Pinned OS packages\n\n")
		fmt.Fprintf(w, "| Package | Pinned | Available | Status | Line |\n|---|---|---|---|---|\n")
		for _, p := range req.Pins {
			avail := p.Available
			if avail == "" {
				avail = "—"
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s | %d |\n",
				p.Package, p.Version, avail, p.Status, p.Line)
		}
		fmt.Fprintf(w, "\n")
	}

	return nil
}

// ── JSON ──────────────────────────────────────────────────────────────────────

type jsonReport struct {
	GeneratedAt string               `json:"generated_at"`
	Image       string               `json:"image"`
	BaseRef     string               `json:"base_ref"`
	Findings    []attribution.Finding `json:"findings"`
	Candidates  []baserec.Candidate  `json:"base_candidates,omitempty"`
	Pins        []pins.Pin           `json:"pins,omitempty"`
}

func renderJSON(w io.Writer, req Request) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Image:       req.Image,
		BaseRef:     req.BaseRef,
		Findings:    req.Findings,
		Candidates:  req.Candidates,
		Pins:        req.Pins,
	})
}

// ── SARIF ─────────────────────────────────────────────────────────────────────

// SARIF 2.1.0 minimal schema (FR-23).
type sarif struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool    `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string         `json:"ruleId"`
	Level     string         `json:"level"`
	Message   sarifMessage   `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

func renderSARIF(w io.Writer, req Request) error {
	// Build deduplicated rule list from findings.
	rulesSeen := map[string]bool{}
	var rules []sarifRule
	for _, f := range req.Findings {
		if rulesSeen[f.CVE] {
			continue
		}
		rulesSeen[f.CVE] = true
		rules = append(rules, sarifRule{
			ID:               f.CVE,
			Name:             f.CVE,
			ShortDescription: sarifMessage{Text: fmt.Sprintf("%s in %s", f.CVE, f.Package)},
			Properties:       map[string]string{"severity": f.Severity},
		})
	}

	var results []sarifResult
	for _, f := range req.Findings {
		level := sarifLevel(f.Severity)
		loc := sarifLocation{
			PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: "Dockerfile"},
				Region:           sarifRegion{StartLine: f.LayerIndex + 1},
			},
		}
		msg := sarifMessage{Text: fmt.Sprintf("%s: %s@%s (owner: %s)", f.CVE, f.Package, f.InstalledVersion, f.Owner)}
		if f.Instruction != nil {
			results = append(results, sarifResult{RuleID: f.CVE, Level: level, Message: msg, Locations: []sarifLocation{loc}})
		} else {
			results = append(results, sarifResult{RuleID: f.CVE, Level: level, Message: msg})
		}
	}

	out := sarif{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "imgowner",
				InformationURI: "https://github.com/Arham1716/imgowner",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func sarifLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

func findingCounts(findings []attribution.Finding) map[attribution.Owner]int {
	m := map[attribution.Owner]int{}
	for _, f := range findings {
		m[f.Owner]++
	}
	return m
}
