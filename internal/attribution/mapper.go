package attribution

import (
	"strings"

	"github.com/Arham1716/imgowner/internal/image"
)

// MapToDockerfileLines sets the Instruction field on each finding by matching
// the finding's layer command text against Dockerfile instruction lines (FR-06).
// Matching order: exact → fuzzy → none.
func MapToDockerfileLines(findings []Finding, layerMap image.LayerMap) []Finding {
	for i := range findings {
		f := &findings[i]
		if f.LayerIndex < 0 || f.LayerIndex >= len(layerMap) {
			continue
		}
		entry := layerMap[f.LayerIndex]
		if entry.Command == "" {
			continue
		}

		line, confidence := matchInstruction(entry.Command, layerMap)
		if line != nil {
			f.Instruction = line
			f.Confidence = confidence
		}
	}
	return findings
}

// matchInstruction attempts exact then fuzzy matching of a layer command
// against the history entries in layerMap.
func matchInstruction(command string, layerMap image.LayerMap) (*DockerfileRef, Confidence) {
	// Exact match: created_by text matches verbatim.
	for _, e := range layerMap {
		if e.Command == command {
			return &DockerfileRef{Line: e.Index + 1, Text: e.Command}, ConfidenceExact
		}
	}

	// Fuzzy match: the command text is a substring of a history entry or vice versa.
	norm := normalise(command)
	for _, e := range layerMap {
		if e.Command == "" {
			continue
		}
		en := normalise(e.Command)
		if strings.Contains(en, norm) || strings.Contains(norm, en) {
			return &DockerfileRef{Line: e.Index + 1, Text: e.Command}, ConfidenceFuzzy
		}
	}

	return nil, ConfidenceNone
}

// normalise strips build-kit prefixes and trims whitespace for fuzzy matching.
func normalise(s string) string {
	s = strings.TrimPrefix(s, "|")
	// BuildKit wraps commands with "|N ARG=val ... /bin/sh -c ..."
	if idx := strings.Index(s, "/bin/sh -c "); idx >= 0 {
		s = s[idx+len("/bin/sh -c "):]
	}
	return strings.TrimSpace(strings.ToLower(s))
}
