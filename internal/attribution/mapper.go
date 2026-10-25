package attribution

import (
	"strings"

	"github.com/Arham1716/imgowner/internal/dockerfile"
	"github.com/Arham1716/imgowner/internal/image"
)

// MapToDockerfileLines sets the Instruction field on each finding by matching
// the finding's layer history text against the Dockerfile's own RUN, COPY and
// ADD instructions (FR-06). Matching order: exact -> fuzzy -> none.
//
// Only the stages whose layers are in the final image are candidates: the
// final stage and any earlier stage it is built FROM. A builder stage's RUN
// never produced a layer of the final image (its output arrives through a
// COPY --from), so matching it would cite a line that isn't the cause.
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
	candidates := collectInstructions(df)
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

// runInstruction is one layer-producing line from the real Dockerfile, ready
// to compare against an image history entry's command text.
type runInstruction struct {
	line int
	copy bool   // COPY/ADD: matched as "<keyword> <args>", never fuzzily against RUN text
	norm string // normalised for matching
	raw  string // original text, for the reported DockerfileRef
}

func collectInstructions(df *dockerfile.File) []runInstruction {
	var out []runInstruction
	if df == nil {
		return out
	}
	for _, stage := range finalImageStages(df) {
		for _, instr := range stage.Lines {
			switch strings.ToUpper(instr.Command) {
			case "RUN":
				out = append(out, runInstruction{line: instr.Line, norm: normalise(instr.Args), raw: instr.Args})
			case "COPY", "ADD":
				// BuildKit records these as "COPY --from=build /src /dst # buildkit",
				// so compare keyword and arguments as written.
				text := strings.ToUpper(instr.Command) + " " + instr.Args
				if raw := strings.TrimSpace(instr.Raw); raw != "" && strings.EqualFold(strings.Fields(raw)[0], instr.Command) {
					text = raw
				}
				out = append(out, runInstruction{line: instr.Line, copy: true, norm: normaliseCopy(text), raw: text})
			}
		}
	}
	return out
}

// finalImageStages returns the final stage and, following FROM <stage-name>,
// every earlier stage whose layers it inherits, outermost first.
func finalImageStages(df *dockerfile.File) []dockerfile.Stage {
	final := df.FinalStage()
	if final == nil {
		return nil
	}
	chain := []dockerfile.Stage{*final}
	seen := map[int]bool{final.Index: true}
	cur := *final
	for {
		parent := -1
		for _, s := range df.Stages {
			if s.Index < cur.Index && s.Name != "" && strings.EqualFold(s.Name, strings.TrimSpace(cur.BaseRef)) {
				parent = s.Index
			}
		}
		if parent < 0 || seen[parent] {
			break
		}
		seen[parent] = true
		cur = df.Stages[parent]
		chain = append([]dockerfile.Stage{cur}, chain...)
	}
	return chain
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

	isCopy := isCopyHistory(layerCommand)
	if isCopy {
		norm = normaliseCopy(layerCommand)
	}
	for _, c := range candidates {
		if c.copy == isCopy && c.norm != "" && c.norm == norm {
			return &DockerfileRef{Line: c.line, Text: c.raw}, ConfidenceExact
		}
	}
	if isCopy {
		// COPY/ADD text is exact or nothing: two COPY lines differ only in
		// paths, and a near-miss would blame the wrong one.
		return nil, ConfidenceNone
	}

	var best *runInstruction
	for i := range candidates {
		c := &candidates[i]
		if c.norm == "" || c.copy {
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

// isCopyHistory reports whether a history entry was made by COPY or ADD
// (BuildKit: "COPY ... # buildkit"; classic builder: "/bin/sh -c #(nop) COPY ...").
func isCopyHistory(s string) bool {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "#(nop)"); i >= 0 {
		s = strings.TrimSpace(s[i+len("#(nop)"):])
	}
	up := strings.ToUpper(s)
	return strings.HasPrefix(up, "COPY ") || strings.HasPrefix(up, "ADD ")
}

// normaliseCopy reduces a COPY/ADD line (from history or the Dockerfile) to
// lowercase "<keyword> <sources...> <dest>". Every --flag is dropped:
// BuildKit's history omits --from=<stage> (a real build records
// "COPY /hello /usr/local/bin/hello # buildkit" for
// "COPY --from=build /hello /usr/local/bin/hello") while keeping others such
// as --chown, so only the paths reliably identify the instruction.
func normaliseCopy(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "#(nop)"); i >= 0 {
		s = s[i+len("#(nop)"):]
	}
	s = strings.TrimSuffix(strings.TrimSpace(s), "# buildkit")
	var kept []string
	for _, f := range strings.Fields(s) {
		if !strings.HasPrefix(f, "--") {
			kept = append(kept, f)
		}
	}
	return strings.ToLower(strings.Join(kept, " "))
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
