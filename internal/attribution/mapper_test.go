package attribution

import (
	"testing"

	"github.com/Arham1716/imgowner/internal/dockerfile"
	"github.com/Arham1716/imgowner/internal/image"
)

// Reproduces the bug found while testing the VS Code extension against a real
// built image: MapToDockerfileLines used LayerEntry.Index + 1 (the layer's
// position inside the image, e.g. "the 3rd layer") as if it were a Dockerfile
// source line number. A curl CVE landed on line 3, a blank line, instead of
// line 7 where the real "RUN apt-get install ... curl=..." is. Those two
// numbers are unrelated except by coincidence.
func TestMapToDockerfileLines_UsesRealLineNotLayerIndex(t *testing.T) {
	src := `# comment
# another comment

FROM python:3.12-slim AS base

# OS packages with exact version pins
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=8.14.1-2+deb13u7 \
    ca-certificates=20250419+deb13u1 \
    openssl=3.5.7-1~deb13u3 \
 && rm -rf /var/lib/apt/lists/*
`
	df, err := dockerfile.ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}

	// A realistic BuildKit history entry: an "RUN |N ... /bin/sh -c ..." wrapper
	// around the same logical command, which real images always carry, never
	// the bare Dockerfile source text.
	layerMap := image.LayerMap{
		{Index: 0, DiffID: "sha256:base0"}, // python:3.12-slim's own layers
		{Index: 1, DiffID: "sha256:base1"},
		{Index: 2, DiffID: "sha256:base2"},
		{Index: 3, DiffID: "sha256:base3"},
		{
			Index:  4,
			DiffID: "sha256:added0",
			Command: "RUN |0 /bin/sh -c apt-get update && apt-get install -y --no-install-recommends " +
				"curl=8.14.1-2+deb13u7 ca-certificates=20250419+deb13u1 openssl=3.5.7-1~deb13u3 " +
				"&& rm -rf /var/lib/apt/lists/* # buildkit",
		},
	}

	findings := []Finding{
		{CVE: "CVE-2026-1", Package: "curl", LayerDiffID: "sha256:added0"},
	}

	got := MapToDockerfileLines(findings, layerMap, df)

	if got[0].Instruction == nil {
		t.Fatal("expected an Instruction to be set")
	}
	if got[0].Instruction.Line != 7 {
		t.Errorf("Instruction.Line = %d, want 7 (the real RUN apt-get line)", got[0].Instruction.Line)
	}
	// Once both sides are whitespace-normalised, the BuildKit wrapper's inner
	// command is byte-identical to the Dockerfile's own joined RUN text here,
	// so this resolves as an exact match -- the strongest possible signal.
	if got[0].Confidence != ConfidenceExact {
		t.Errorf("Confidence = %v, want exact", got[0].Confidence)
	}
}

// Multiple findings sharing one layer (e.g. three CVEs all in the curl/ssl
// RUN) must all resolve to the same line, computed once.
func TestMapToDockerfileLines_MultipleFindingsSameLayer(t *testing.T) {
	src := "FROM debian:12-slim\nRUN apt-get install -y curl=1.2.3\n"
	df, err := dockerfile.ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}

	layerMap := image.LayerMap{
		{Index: 0, DiffID: "sha256:base0"},
		{Index: 1, DiffID: "sha256:added0", Command: "RUN /bin/sh -c apt-get install -y curl=1.2.3 # buildkit"},
	}
	findings := []Finding{
		{CVE: "CVE-A", LayerDiffID: "sha256:added0"},
		{CVE: "CVE-B", LayerDiffID: "sha256:added0"},
	}

	got := MapToDockerfileLines(findings, layerMap, df)
	for _, f := range got {
		if f.Instruction == nil || f.Instruction.Line != 2 {
			t.Errorf("%s: expected line 2, got %+v", f.CVE, f.Instruction)
		}
	}
}

// The actual bug found via the VS Code extension: LayerEntry.Index counts a
// layer's position among diff-producing layers only (what Classify needs),
// while LayerMap holds one entry per history record, empty layers included.
// A WORKDIR between the base image and the RUN that follows it makes those
// two counts diverge -- Index says "1" (the second diff-producing layer), but
// its real position in layerMap is 2 (base, WORKDIR, this one). Looking it up
// as layerMap[1] used to land on the WORKDIR entry -- empty Command, no
// match, or worse, a coincidentally-real but wrong one -- instead of this
// layer's actual Command. Matching by LayerDiffID sidesteps this entirely.
func TestMapToDockerfileLines_EmptyLayerDoesNotShiftLookup(t *testing.T) {
	src := "FROM debian:12-slim\nWORKDIR /app\nRUN apt-get install -y curl=1.2.3\n"
	df, err := dockerfile.ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}

	layerMap := image.LayerMap{
		{Index: 0, DiffID: "sha256:base0"},                                                                      // slice position 0
		{Index: 1, IsEmpty: true, Command: "WORKDIR /app"},                                                      // slice position 1, no DiffID -- Index does NOT advance
		{Index: 1, DiffID: "sha256:added0", Command: "RUN /bin/sh -c apt-get install -y curl=1.2.3 # buildkit"}, // slice position 2, Index still only 1
	}
	findings := []Finding{{CVE: "CVE-A", LayerDiffID: "sha256:added0"}}

	got := MapToDockerfileLines(findings, layerMap, df)
	if got[0].Instruction == nil {
		t.Fatal("expected a match; LayerDiffID lookup must not be thrown off by the empty WORKDIR layer")
	}
	if got[0].Instruction.Line != 3 {
		t.Errorf("Instruction.Line = %d, want 3 (the RUN line, not the WORKDIR line it would land on "+
			"if looked up as layerMap[LayerIndex])", got[0].Instruction.Line)
	}
}

// An image history entry with no matching Dockerfile RUN line (for example a
// base-image layer whose own build history is still present in the final
// image's history list) must leave Instruction unset rather than guess.
func TestMapToDockerfileLines_NoMatchLeavesInstructionNil(t *testing.T) {
	df, err := dockerfile.ParseBytes([]byte("FROM debian:12-slim\nRUN echo hello\n"))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	layerMap := image.LayerMap{
		{Index: 0, DiffID: "sha256:a", Command: "RUN /bin/sh -c apt-get install -y something-unrelated"},
	}
	findings := []Finding{{CVE: "CVE-X", LayerDiffID: "sha256:a"}}

	got := MapToDockerfileLines(findings, layerMap, df)
	if got[0].Instruction != nil {
		t.Errorf("expected no match, got %+v", got[0].Instruction)
	}
	if got[0].Confidence != "" && got[0].Confidence != ConfidenceNone {
		t.Errorf("expected ConfidenceNone or unset, got %v", got[0].Confidence)
	}
}

// A finding with no DiffID at all (Trivy reported no layer info, e.g. a
// squashed image) must be skipped, not matched against layerMap[0] by
// accident of a zero-value LayerIndex.
func TestMapToDockerfileLines_EmptyDiffIDIsSkipped(t *testing.T) {
	df, err := dockerfile.ParseBytes([]byte("FROM debian:12-slim\nRUN apt-get install -y curl\n"))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	layerMap := image.LayerMap{
		{Index: 0, DiffID: "sha256:a", Command: "RUN /bin/sh -c apt-get install -y curl"},
	}
	findings := []Finding{{CVE: "CVE-X", LayerDiffID: ""}}

	got := MapToDockerfileLines(findings, layerMap, df)
	if got[0].Instruction != nil {
		t.Errorf("a finding with no LayerDiffID must not match anything, got %+v", got[0].Instruction)
	}
}

func TestMapToDockerfileLines_NilDockerfileIsSafe(t *testing.T) {
	layerMap := image.LayerMap{{Index: 0, DiffID: "sha256:a", Command: "RUN /bin/sh -c echo hi"}}
	findings := []Finding{{CVE: "CVE-X", LayerDiffID: "sha256:a"}}

	got := MapToDockerfileLines(findings, layerMap, nil)
	if got[0].Instruction != nil {
		t.Errorf("nil dockerfile should yield no match, got %+v", got[0].Instruction)
	}
}

func TestNormalise(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{
			"buildkit wrapper with arg prefix",
			"RUN |1 BASE_TAG=12-slim /bin/sh -c apt-get update # buildkit",
			"apt-get update",
		},
		{
			"buildkit wrapper no args",
			"RUN /bin/sh -c echo hi # buildkit",
			"echo hi",
		},
		{
			"plain dockerfile source, no wrapper",
			"apt-get update",
			"apt-get update",
		},
		{
			"collapses embedded newlines from a joined multi-line RUN",
			"apt-get update &&\n    apt-get install -y curl",
			"apt-get update && apt-get install -y curl",
		},
		{
			"case insensitive",
			"APT-GET UPDATE",
			"apt-get update",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalise(tc.in); got != tc.want {
				t.Errorf("normalise(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMatchInstruction_PrefersExactOverFuzzy(t *testing.T) {
	candidates := []runInstruction{
		{line: 3, norm: "apt-get install -y curl", raw: "apt-get install -y curl"},
		{line: 7, norm: "apt-get install -y curl=1.2.3", raw: "apt-get install -y curl=1.2.3"},
	}
	ref, conf := matchInstruction("apt-get install -y curl", candidates)
	if ref == nil || ref.Line != 3 {
		t.Fatalf("expected exact match at line 3, got %+v", ref)
	}
	if conf != ConfidenceExact {
		t.Errorf("expected ConfidenceExact, got %v", conf)
	}
}

func TestMatchInstruction_FuzzyPrefersLongestMatch(t *testing.T) {
	// Neither candidate equals the full layer command exactly (it has an
	// extra cleanup step neither candidate's text includes), so this must
	// fall to fuzzy matching -- and a short, generic RUN line ("apt-get
	// update") must not win over a more specific one just because it also
	// appears as a substring.
	candidates := []runInstruction{
		{line: 2, norm: "apt-get update", raw: "apt-get update"},
		{line: 3, norm: "apt-get update && apt-get install -y curl=1.2.3", raw: "apt-get update && apt-get install -y curl=1.2.3"},
	}
	ref, conf := matchInstruction(
		"/bin/sh -c apt-get update && apt-get install -y curl=1.2.3 && rm -rf /var/lib/apt/lists/* # buildkit",
		candidates,
	)
	if ref == nil || ref.Line != 3 {
		t.Fatalf("expected the more specific line 3 to win, got %+v", ref)
	}
	if conf != ConfidenceFuzzy {
		t.Errorf("expected ConfidenceFuzzy, got %v", conf)
	}
}
