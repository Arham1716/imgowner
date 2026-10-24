package attribution

import (
	"strings"

	"github.com/Arham1716/imgowner/internal/dockerfile"
	"github.com/Arham1716/imgowner/internal/image"
)

// MapToDockerfileLines sets the Instruction field on each finding by matching
// the finding's layer history text against the Dockerfile's own RUN
// instructions (FR-06). Matching order: exact -> fuzzy -> none.
//
// The image's build history ("created_by") is BuildKit's own record of the
// command that produced a layer; it carries no Dockerfile line number, so it
// is matched against the real parsed Dockerfile's RUN text to find one.
//
// Findings are looked up by LayerDiffID, not LayerIndex: LayerEntry.Index
// counts a layer's position among layers that produced a filesystem diff
// (which is what Classify needs to compare against a base layer count), while
// LayerMap itself holds one entry per history record, empty layers (WORKDIR,
// ENV, CMD, ...) included. Any empty layer earlier in the image's history
// makes those two counts diverge, so treating LayerIndex as a slice position
// into LayerMap silently selects the wrong entry -- found via the VS Code
// extension against a real multi-stage image, where every CVE resolved to the
// wrong line once the image had any empty layer before the one in question
// (essentially always, since WORKDIR/CMD/ENV are normal in any Dockerfile).
func MapToDockerfileLines(findings []Finding, layerMap image.LayerMap, df *dockerfile.File) []Finding {
	candidates := collectRunInstructions(df)
	cache := make(map[string]*DockerfileRef)
	confidenceCache := make(map[string]Confidence)

	for i := range findings {
		f := &findings[i]
		if f.LayerDiffID == "" {
			continue
		}
		entry := layerMap.FindByDiffID(f.LayerDiffID)
		if entry == nil || entry.Command == "" {
			continue
		}

		ref, ok := cache[f.LayerDiffID]
		if !ok {
			ref, confidenceCache[f.LayerDiffID] = matchInstruction(entry.Command, candidates)
			cache[f.LayerDiffID] = ref
		}
		if ref != nil {
			f.Instruction = ref
			f.Confidence = confidenceCache[f.LayerDiffID]
		}
	}
	return findings
}

// runInstruction is one RUN line from the real Dockerfile, ready to compare
// against an image history entry's command text.
type runInstruction struct {
	line int
	norm string // normalised for matching
	raw  string // original text, for the reported DockerfileRef
}

func collectRunInstructions(df *dockerfile.File) []runInstruction {
	var out []runInstruction
	if df == nil {
		return out
	}
	for _, stage := range df.Stages {
		for _, instr := range stage.Lines {
			if !strings.EqualFold(instr.Command, "RUN") {
				continue
			}
			out = append(out, runInstruction{
				line: instr.Line,
				norm: normalise(instr.Args),
				raw:  instr.Args,
			})
		}
	}
	return out
}

// matchInstruction compares an image layer's history text against every RUN
// line in the real Dockerfile, exact match first, then substring containment
// in either direction, preferring the most specific (longest) fuzzy match so
// a short RUN line doesn't win over a more precise one.
func matchInstruction(layerCommand string, candidates []runInstruction) (*DockerfileRef, Confidence) {
	norm := normalise(layerCommand)
	if norm == "" {
		return nil, ConfidenceNone
	}

	for _, c := range candidates {
		if c.norm != "" && c.norm == norm {
			return &DockerfileRef{Line: c.line, Text: c.raw}, ConfidenceExact
		}
	}

	var best *runInstruction
	for i := range candidates {
		c := &candidates[i]
		if c.norm == "" {
			continue
		}
		if strings.Contains(norm, c.norm) || strings.Contains(c.norm, norm) {
			if best == nil || len(c.norm) > len(best.norm) {
				best = c
			}
		}
	}
	if best != nil {
		return &DockerfileRef{Line: best.line, Text: best.raw}, ConfidenceFuzzy
	}

	return nil, ConfidenceNone
}

// normalise strips BuildKit's layer-history wrapper (e.g. "RUN |1 ARG=val
// /bin/sh -c <command> # buildkit") and collapses all whitespace -- including
// the embedded newlines/tabs a Dockerfile's own line-continued RUN leaves in
// its joined instruction text -- so the two sides can be compared as plain,
// single-line, lowercased strings regardless of which one is which.
func normalise(s string) string {
	s = strings.TrimPrefix(s, "|")
	if idx := strings.Index(s, "/bin/sh -c "); idx >= 0 {
		s = s[idx+len("/bin/sh -c "):]
	}
	s = strings.TrimSuffix(strings.TrimSpace(s), "# buildkit")
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}
