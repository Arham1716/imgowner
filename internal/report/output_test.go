package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/baserec"
)

func TestParseFormats(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
		ok   bool
	}{
		{[]string{"md,json,sarif"}, "md,json,sarif", true}, // the README / Action form
		{[]string{"md", "json"}, "md,json", true},
		{[]string{" JSON , markdown "}, "json,md", true},
		{[]string{"json", "json,md"}, "json,md", true},
		{[]string{"xml"}, "", false},
		{[]string{"md,pdf"}, "", false},
		{[]string{","}, "", false},
		{nil, "", false},
	} {
		got, err := ParseFormats(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ParseFormats(%q) error = %v, want ok=%v", c.in, err, c.ok)
			continue
		}
		if c.ok && strings.Join(got, ",") != c.want {
			t.Errorf("ParseFormats(%q) = %v, want %s", c.in, got, c.want)
		}
	}
}

// The v0.5.0 default printed Markdown followed by JSON on stdout, which no
// tool can parse. Several formats now need an output directory.
func TestWrite_SeveralFormatsCannotShareStdout(t *testing.T) {
	for _, dir := range []string{"", Stdout} {
		if _, err := Write(Request{Formats: []string{"md", "json"}, OutputDir: dir}); err == nil {
			t.Errorf("OutputDir %q: md+json on stdout was accepted", dir)
		}
	}
}

func TestWrite_LeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := Write(Request{Findings: sampleFindings(), OutputDir: dir, Formats: []string{"md,json,sarif"}}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
	if len(entries) != 3 {
		t.Errorf("want 3 files, got %d", len(entries))
	}
}

func TestRenderMarkdown_EscapesTableCells(t *testing.T) {
	f := attribution.Finding{
		CVE: "CVE-1", Severity: "HIGH", Package: "p", Owner: attribution.OwnerAddedOS,
		Instruction: &attribution.DockerfileRef{Line: 3, Text: "apt-get install a | tee log &&\nrm -rf x"},
	}
	var b strings.Builder
	if err := renderMarkdown(&b, Request{Findings: []attribution.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(line, "| CVE-1 ") {
			// 6 columns -> 7 unescaped pipes.
			if n := strings.Count(strings.ReplaceAll(line, `\|`, ""), "|"); n != 7 {
				t.Errorf("row has %d column separators, want 7: %q", n, line)
			}
			return
		}
	}
	t.Fatalf("finding row missing (a newline in the instruction split it):\n%s", b.String())
}

// FR-08: unattributed findings appear with their reason, not just a count.
func TestRenderMarkdown_ListsUnattributedReasons(t *testing.T) {
	fs := []attribution.Finding{
		{CVE: "CVE-1", Owner: attribution.OwnerUnattributed, UnattributedReason: "base image boundary unverified"},
		{CVE: "CVE-2", Owner: attribution.OwnerUnattributed, UnattributedReason: "base image boundary unverified"},
	}
	var b strings.Builder
	if err := renderMarkdown(&b, Request{Findings: fs}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "## Unattributed findings") || !strings.Contains(b.String(), "| base image boundary unverified | 2 |") {
		t.Errorf("unattributed section missing or wrong:\n%s", b.String())
	}
}

// FR-11: the recommendation is a paste-ready, digest-pinned FROM line.
func TestRenderMarkdown_RecommendsADigestPinnedFromLine(t *testing.T) {
	cs := []baserec.Candidate{
		{Tag: "3.12.1-slim", Ref: "python:3.12.1-slim@sha256:aaa", CVEsRemoved: 3, CVEsRemaining: 9},
		{Tag: "3.12.2-slim", Ref: "python:3.12.2-slim@sha256:bbb", CVEsRemoved: 7, CVEsRemaining: 5},
		{Tag: "3.12.3-slim", Failed: true, FailReason: "rate limited"},
	}
	var b strings.Builder
	if err := renderMarkdown(&b, Request{Candidates: cs}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "FROM python:3.12.2-slim@sha256:bbb") {
		t.Errorf("best candidate's FROM line missing:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| 3.12.3-slim") && strings.Count(line, "|") != 5 {
			t.Errorf("failed-candidate row has the wrong column count: %q", line)
		}
	}
}

func TestRenderSARIF_UsesTheRealDockerfilePath(t *testing.T) {
	wd, _ := os.Getwd()
	f := attribution.Finding{CVE: "CVE-1", Instruction: &attribution.DockerfileRef{Line: 2, Text: "RUN x"}}
	var b strings.Builder
	if err := renderSARIF(&b, Request{Findings: []attribution.Finding{f}, Dockerfile: filepath.Join(wd, "build", "app.Dockerfile")}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "build/app.Dockerfile" {
		t.Errorf("SARIF uri = %q, want build/app.Dockerfile", got)
	}
}

// FR-26/27: the ci report and PR comment carry the policy verdict and say
// when the pin check was skipped.
func TestRenderMarkdown_VerdictAndPinsNote(t *testing.T) {
	var b strings.Builder
	err := renderMarkdown(&b, Request{Verdict: "failed — 2 finding(s)", PinsNote: "Pin check skipped — no container runtime detected"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"**Policy:** failed — 2 finding(s)", "> Pin check skipped — no container runtime detected"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in:\n%s", want, b.String())
		}
	}
}
