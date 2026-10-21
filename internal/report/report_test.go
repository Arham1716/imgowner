package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/baserec"
	"github.com/Arham1716/imgowner/internal/pins"
)

func sampleFindings() []attribution.Finding {
	return []attribution.Finding{
		{
			CVE: "CVE-2024-1111", Severity: "CRITICAL", Package: "openssl",
			InstalledVersion: "3.0.11", Owner: attribution.OwnerAddedOS,
			Instruction: &attribution.DockerfileRef{Line: 4, Text: "RUN apt-get install -y openssl=3.0.11"},
		},
		{
			CVE: "CVE-2024-2222", Severity: "HIGH", Package: "curl",
			InstalledVersion: "7.88.1", Owner: attribution.OwnerAddedOS,
			Instruction: &attribution.DockerfileRef{Line: 3, Text: "RUN apt-get install -y curl=7.88.1"},
		},
		{
			CVE: "CVE-2024-3333", Severity: "LOW", Package: "libc6",
			InstalledVersion: "2.36", Owner: attribution.OwnerBase,
			// No Instruction: base-image findings have no Dockerfile line.
		},
	}
}

func TestRenderMarkdown_ContainsExpectedSections(t *testing.T) {
	var buf bytes.Buffer
	req := Request{
		Image:    "myapp:latest",
		BaseRef:  "debian:12-slim",
		Findings: sampleFindings(),
		Candidates: []baserec.Candidate{
			{Tag: "12.5-slim", CVEsRemoved: 10, CVEsRemaining: 2},
			{Tag: "12.6-slim", Failed: true, FailReason: "scan timed out"},
		},
		Pins: []pins.Pin{
			{Package: "curl", Version: "7.88.1-10", Available: "7.88.1-12", Status: pins.StatusUpdateAvailable, Line: 3},
		},
	}
	if err := renderMarkdown(&buf, req); err != nil {
		t.Fatalf("renderMarkdown: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"myapp:latest", "debian:12-slim",
		"CVE-2024-1111", "CVE-2024-3333",
		"12.5-slim", "scan failed: scan timed out",
		"curl", "7.88.1-12",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q", want)
		}
	}
}

func TestRenderMarkdown_EmptyFindingsOmitsFindingsSection(t *testing.T) {
	var buf bytes.Buffer
	if err := renderMarkdown(&buf, Request{Image: "x", BaseRef: "y"}); err != nil {
		t.Fatalf("renderMarkdown: %v", err)
	}
	if strings.Contains(buf.String(), "### Findings") {
		t.Error("a report with no findings should not print a Findings section header")
	}
}

// A write failure partway through must stop immediately rather than panic or
// keep writing to a broken destination.
func TestRenderMarkdown_WriteFailureIsPropagated(t *testing.T) {
	err := renderMarkdown(failingWriter{}, Request{Image: "x", BaseRef: "y", Findings: sampleFindings()})
	if err == nil {
		t.Fatal("expected the write error to propagate, got nil")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestRenderJSON_FieldsAreSnakeCase(t *testing.T) {
	var buf bytes.Buffer
	req := Request{Image: "myapp:latest", BaseRef: "debian:12-slim", Findings: sampleFindings()}
	if err := renderJSON(&buf, req); err != nil {
		t.Fatalf("renderJSON: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, key := range []string{"generated_at", "image", "base_ref", "findings"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("JSON report missing expected key %q; got keys %v", key, keysOf(decoded))
		}
	}

	findings, ok := decoded["findings"].([]any)
	if !ok || len(findings) != 3 {
		t.Fatalf("expected 3 findings in JSON output, got %v", decoded["findings"])
	}
	first, ok := findings[0].(map[string]any)
	if !ok {
		t.Fatalf("finding is not an object: %v", findings[0])
	}
	for _, key := range []string{"cve", "severity", "package", "installed_version", "owner"} {
		if _, ok := first[key]; !ok {
			t.Errorf("finding missing expected snake_case key %q; got keys %v", key, keysOf(first))
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRenderSARIF_IsValidAndDeduplicatesRules(t *testing.T) {
	var buf bytes.Buffer
	findings := append(sampleFindings(),
		attribution.Finding{CVE: "CVE-2024-1111", Severity: "CRITICAL", Package: "openssl-other-target", Owner: attribution.OwnerBase})

	if err := renderSARIF(&buf, Request{Findings: findings}); err != nil {
		t.Fatalf("renderSARIF: %v", err)
	}

	var doc sarif
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid SARIF JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("SARIF version: want 2.1.0, got %s", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %d", len(doc.Runs))
	}

	// 4 findings in, but CVE-2024-1111 appears twice, so only 3 distinct rules.
	if got := len(doc.Runs[0].Tool.Driver.Rules); got != 3 {
		t.Errorf("expected 3 deduplicated rules, got %d", got)
	}
	// Every finding still produces its own result, duplicates included.
	if got := len(doc.Runs[0].Results); got != 4 {
		t.Errorf("expected 4 results (one per finding), got %d", got)
	}
}

func TestRenderSARIF_UsesInstructionLineWhenPresent(t *testing.T) {
	var buf bytes.Buffer
	findings := []attribution.Finding{
		{CVE: "CVE-A", Severity: "HIGH", Owner: attribution.OwnerAddedOS,
			Instruction: &attribution.DockerfileRef{Line: 7}},
		{CVE: "CVE-B", Severity: "LOW", Owner: attribution.OwnerBase}, // no instruction
	}
	if err := renderSARIF(&buf, Request{Findings: findings}); err != nil {
		t.Fatalf("renderSARIF: %v", err)
	}

	var doc sarif
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	results := doc.Runs[0].Results

	withLoc := findResult(t, results, "CVE-A")
	if len(withLoc.Locations) != 1 || withLoc.Locations[0].PhysicalLocation.Region.StartLine != 7 {
		t.Errorf("CVE-A should report Dockerfile line 7, got %+v", withLoc.Locations)
	}

	withoutLoc := findResult(t, results, "CVE-B")
	if len(withoutLoc.Locations) != 0 {
		t.Errorf("CVE-B has no Instruction and should carry no location, got %+v", withoutLoc.Locations)
	}
}

func findResult(t *testing.T, results []sarifResult, cve string) sarifResult {
	t.Helper()
	for _, r := range results {
		if r.RuleID == cve {
			return r
		}
	}
	t.Fatalf("no SARIF result found for %s", cve)
	return sarifResult{}
}

func TestSarifLevel(t *testing.T) {
	cases := []struct{ severity, want string }{
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
		{"UNKNOWN", "note"},
		{"", "note"},
	}
	for _, tc := range cases {
		if got := sarifLevel(tc.severity); got != tc.want {
			t.Errorf("sarifLevel(%q) = %q, want %q", tc.severity, got, tc.want)
		}
	}
}

func TestWrite_CreatesOneFilePerFormat(t *testing.T) {
	dir := t.TempDir()
	req := Request{
		Image: "x", BaseRef: "y", Findings: sampleFindings(),
		OutputDir: dir,
		Formats:   []string{"md", "json", "sarif"},
	}
	if err := Write(req); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for _, name := range []string{"imgowner-report.md", "imgowner-report.json", "imgowner-report.sarif"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s was created but is empty", name)
		}
	}
}

func TestWrite_UnknownFormatIsIgnored(t *testing.T) {
	dir := t.TempDir()
	req := Request{Image: "x", BaseRef: "y", OutputDir: dir, Formats: []string{"yaml"}}
	if err := Write(req); err != nil {
		t.Fatalf("an unrecognised format should be silently skipped, not error: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("no file should have been written for an unknown format, found %d", len(entries))
	}
}

func TestWriteToWriter_RendersOnlyFirstFormat(t *testing.T) {
	var buf bytes.Buffer
	req := Request{Image: "x", BaseRef: "y", Formats: []string{"json", "sarif"}}
	if err := WriteToWriter(&buf, req); err != nil {
		t.Fatalf("WriteToWriter: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("expected JSON (the first format) to be rendered, got invalid JSON: %v", err)
	}
	if _, ok := decoded["$schema"]; ok {
		t.Error("WriteToWriter rendered sarif instead of the first format (json)")
	}
}

func TestWriteToWriter_NoFormatsIsNoop(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteToWriter(&buf, Request{}); err != nil {
		t.Fatalf("no formats should not error, got: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("no formats should write nothing, got %d bytes", buf.Len())
	}
}
