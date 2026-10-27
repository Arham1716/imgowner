package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/baserec"
	"github.com/Arham1716/imgowner/internal/pins"
)

// Request bundles everything needed to write a report.
type Request struct {
	Image      string
	Digest     string // digest actually scanned (pipeline.AttributeResult.Digest); empty if unresolved
	BaseRef    string
	Findings   []attribution.Finding
	Candidates []baserec.Candidate
	Pins       []pins.Pin
	OutputDir  string   // directory to write files into; "" or "-" = stdout (one format only)
	Formats    []string // "md", "json", "sarif" (see ParseFormats)
	Dockerfile string   // Dockerfile path, used as the SARIF artifact location
}

// Stdout is the OutputDir value that writes a single format to standard output.
const Stdout = "-"

// knownFormats maps every accepted spelling to its canonical name.
var knownFormats = map[string]string{"md": "md", "markdown": "md", "json": "json", "sarif": "sarif"}

// ParseFormats normalises --format / report.formats values: each value may
// hold several comma-separated formats ("md,json,sarif", as the README and
// the GitHub Action pass them), names are case-insensitive, duplicates are
// dropped, and an unknown name is an error rather than silently producing
// nothing.
func ParseFormats(values []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			name := strings.ToLower(strings.TrimSpace(part))
			if name == "" {
				continue
			}
			canon, ok := knownFormats[name]
			if !ok {
				return nil, fmt.Errorf("unknown report format %q (use md, json or sarif)", part)
			}
			if !seen[canon] {
				seen[canon] = true
				out = append(out, canon)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no report format selected (use md, json or sarif)")
	}
	return out, nil
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

var renderers = map[string]func(io.Writer, Request) error{
	"md": renderMarkdown, "json": renderJSON, "sarif": renderSARIF,
}

// Write produces every requested format (FR-28): one file per format under
// req.OutputDir, or a single format on stdout when OutputDir is "" or "-".
// Several formats on stdout used to be concatenated (Markdown followed by
// JSON), which nothing can parse, so that is now an error. It returns the
// paths written.
func Write(req Request) ([]string, error) {
	formats, err := ParseFormats(req.Formats)
	if err != nil {
		return nil, err
	}
	if req.OutputDir == "" || req.OutputDir == Stdout {
		if len(formats) > 1 {
			return nil, fmt.Errorf("report: %d formats (%s) can't share stdout; pass --output-dir <dir> or a single --format",
				len(formats), strings.Join(formats, ", "))
		}
		return nil, renderers[formats[0]](os.Stdout, req)
	}
	if err := os.MkdirAll(req.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("report: mkdir %s: %w", req.OutputDir, err)
	}
	var written []string
	for _, f := range formats {
		path, err := writeFile(req, f, renderers[f])
		if err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

// writeFile renders into a temporary file in the output directory and renames
// it into place, so an interrupted run never leaves a truncated report that a
// later CI step would read as complete.
func writeFile(req Request, ext string, render func(io.Writer, Request) error) (string, error) {
	path := filepath.Join(req.OutputDir, "imgowner-report."+ext)
	tmp, err := os.CreateTemp(req.OutputDir, ".imgowner-report-*."+ext)
	if err != nil {
		return "", fmt.Errorf("report: create %s: %w", path, err)
	}
	if err := render(tmp, req); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", err
	}
	// Close explicitly, not deferred: a failure flushing to disk (e.g. the
	// volume filled up mid-write) must be reported, not silently swallowed.
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("report: closing %s: %w", path, err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { // CreateTemp makes 0600
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("report: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("report: %w", err)
	}
	return path, nil
}

// ── Markdown ──────────────────────────────────────────────────────────────────

// errWriter accumulates the first write error so a long sequence of Fprintf
// calls does not need an error check after each one; every write becomes a
// no-op once err is set, and the caller checks err exactly once at the end.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}

func renderMarkdown(w io.Writer, req Request) error {
	counts := findingCounts(req.Findings)
	ew := &errWriter{w: w}

	ew.printf("# imgowner report\n\n")
	if req.Digest != "" {
		ew.printf("**Image:** `%s` (`%s`)  \n**Base:** `%s`  \n**Generated:** %s\n\n",
			req.Image, req.Digest, req.BaseRef, time.Now().UTC().Format(time.RFC3339))
	} else {
		ew.printf("**Image:** `%s`  \n**Base:** `%s`  \n**Generated:** %s\n\n",
			req.Image, req.BaseRef, time.Now().UTC().Format(time.RFC3339))
	}

	ew.printf("## CVE attribution\n\n")
	ew.printf("| Owner | Count |\n|---|---|\n")
	ew.printf("| base | %d |\n", counts[attribution.OwnerBase])
	ew.printf("| added-os | %d |\n", counts[attribution.OwnerAddedOS])
	ew.printf("| app | %d |\n", counts[attribution.OwnerApp])
	ew.printf("| unattributed | %d |\n\n", counts[attribution.OwnerUnattributed])

	if len(req.Findings) > 0 {
		ew.printf("### Findings\n\n")
		ew.printf("| CVE | Severity | Package | Version | Owner | Instruction |\n|---|---|---|---|---|---|\n")
		for _, f := range req.Findings {
			instr := ""
			if f.Instruction != nil {
				instr = fmt.Sprintf("line %d: %s", f.Instruction.Line, f.Instruction.Text)
			}
			ew.printf("| %s | %s | %s | %s | %s | %s |\n",
				cell(f.CVE), cell(f.Severity), cell(f.Package), cell(f.InstalledVersion), cell(string(f.Owner)), cell(instr))
		}
		ew.printf("\n")
	}

	// FR-08: every unattributed finding is listed with the reason, never just
	// counted, so the reader knows what to fix.
	if reasons := unattributedReasons(req.Findings); len(reasons) > 0 {
		ew.printf("## Unattributed findings\n\n")
		ew.printf("| Reason | Findings |\n|---|---|\n")
		for _, r := range reasons {
			ew.printf("| %s | %d |\n", cell(r.reason), r.count)
		}
		ew.printf("\n")
	}

	if len(req.Candidates) > 0 {
		ew.printf("## Base image recommendations\n\n")
		if best := bestCandidate(req.Candidates); best != nil {
			// FR-11: a digest-pinned FROM line that can be pasted as is.
			ew.printf("Recommended:\n\n```dockerfile\nFROM %s\n```\n\n", best.Ref)
		}
		ew.printf("| Tag | CVEs removed | CVEs remaining | Note |\n|---|---|---|---|\n")
		for _, c := range req.Candidates {
			if c.Failed {
				ew.printf("| %s | — | — | scan failed: %s |\n", cell(c.Tag), cell(c.FailReason))
			} else {
				ew.printf("| %s | %d | %d | |\n", cell(c.Tag), c.CVEsRemoved, c.CVEsRemaining)
			}
		}
		ew.printf("\n")
	}

	if len(req.Pins) > 0 {
		ew.printf("## Pinned OS packages\n\n")
		ew.printf("| Package | Pinned | Available | Status | Line |\n|---|---|---|---|---|\n")
		for _, p := range req.Pins {
			avail := p.Available
			if avail == "" {
				avail = "—"
			}
			ew.printf("| %s | %s | %s | %s | %d |\n",
				cell(p.Package), cell(p.Version), cell(avail), cell(string(p.Status)), p.Line)
		}
		ew.printf("\n")
	}

	return ew.err
}

// cell makes s safe inside a Markdown table cell: a '|' would start a new
// column and a newline would end the row (a multi-line RUN instruction did
// both), breaking every row after it in the report and the PR comment.
func cell(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.TrimSpace(s)
}

type reasonCount struct {
	reason string
	count  int
}

// unattributedReasons groups unattributed findings by reason, largest first.
func unattributedReasons(findings []attribution.Finding) []reasonCount {
	counts := map[string]int{}
	var order []string
	for _, f := range findings {
		if f.Owner != attribution.OwnerUnattributed {
			continue
		}
		r := f.UnattributedReason
		if r == "" {
			r = "no reason recorded"
		}
		if counts[r] == 0 {
			order = append(order, r)
		}
		counts[r]++
	}
	out := make([]reasonCount, 0, len(order))
	for _, r := range order {
		out = append(out, reasonCount{r, counts[r]})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].count > out[j].count })
	return out
}

// bestCandidate is the scanned candidate that removes the most CVEs, or nil
// when none removes any (recommending a no-op change helps nobody).
func bestCandidate(cs []baserec.Candidate) *baserec.Candidate {
	var best *baserec.Candidate
	for i := range cs {
		c := &cs[i]
		if c.Failed || c.Ref == "" || c.CVEsRemoved <= 0 {
			continue
		}
		if best == nil || c.CVEsRemoved > best.CVEsRemoved ||
			(c.CVEsRemoved == best.CVEsRemoved && c.CVEsRemaining < best.CVEsRemaining) {
			best = c
		}
	}
	return best
}

// ── JSON ──────────────────────────────────────────────────────────────────────

type jsonReport struct {
	GeneratedAt string                `json:"generated_at"`
	Image       string                `json:"image"`
	Digest      string                `json:"digest,omitempty"`
	BaseRef     string                `json:"base_ref"`
	Findings    []attribution.Finding `json:"findings"`
	Candidates  []baserec.Candidate   `json:"base_candidates,omitempty"`
	Pins        []pins.Pin            `json:"pins,omitempty"`
}

func renderJSON(w io.Writer, req Request) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Image:       req.Image,
		Digest:      req.Digest,
		BaseRef:     req.BaseRef,
		Findings:    req.Findings,
		Candidates:  req.Candidates,
		Pins:        req.Pins,
	})
}

// ── SARIF ─────────────────────────────────────────────────────────────────────

// SARIF 2.1.0 minimal schema (FR-23).
type sarif struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
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
		line := 1
		if f.Instruction != nil && f.Instruction.Line > 0 {
			line = f.Instruction.Line
		}
		loc := sarifLocation{
			PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: sarifURI(req.Dockerfile)},
				Region:           sarifRegion{StartLine: line},
			},
		}
		text := fmt.Sprintf("%s: %s@%s (owner: %s)", f.CVE, f.Package, f.InstalledVersion, f.Owner)
		if f.Owner == attribution.OwnerUnattributed && f.UnattributedReason != "" {
			text += "; not attributed: " + f.UnattributedReason
		}
		msg := sarifMessage{Text: text}
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

// sarifURI is the Dockerfile's location relative to the repository root as
// SARIF expects it: forward slashes, no leading "./". Code scanning matches
// it against repository paths, so a Dockerfile in a subdirectory must not be
// reported as the root "Dockerfile".
func sarifURI(dockerfile string) string {
	if dockerfile == "" {
		return "Dockerfile"
	}
	p := filepath.ToSlash(filepath.Clean(dockerfile))
	if abs, err := filepath.Abs(dockerfile); err == nil {
		if wd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(wd, abs); err == nil && !strings.HasPrefix(rel, "..") {
				p = filepath.ToSlash(rel)
			}
		}
	}
	return strings.TrimPrefix(p, "./")
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
