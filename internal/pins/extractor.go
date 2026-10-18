package pins

import (
	"bytes"
	"strings"

	"github.com/Arham1716/imgowner/internal/dockerfile"
)

// Extract parses all RUN instructions in the Dockerfile and returns one Pin per
// exact-pinned OS package found in apt-get/apt/apk install|add invocations
// (Story 2.1, FR-12). content is the raw Dockerfile bytes.
func Extract(content []byte, df *dockerfile.File) ([]Pin, error) {
	lineOffsets := buildLineOffsets(content)
	var pins []Pin

	for _, stage := range df.Stages {
		for _, instr := range stage.Lines {
			if !strings.EqualFold(instr.Command, "RUN") {
				continue
			}
			found := extractFromRun(instr.Args, instr.Line, content, lineOffsets, stage.Name)
			pins = append(pins, found...)
		}
	}
	return pins, nil
}

// extractFromRun tokenises a RUN instruction's argument string and returns
// any exact-pinned packages from apt/apk install|add invocations.
func extractFromRun(runArgs string, instrLine int, content []byte, lineOffsets []int, stage string) []Pin {
	// Normalise line continuations and split into individual commands.
	normalised := strings.ReplaceAll(runArgs, "\\\n", " ")
	cmds := splitCommands(normalised)

	var pins []Pin
	for _, cmd := range cmds {
		tokens := tokenise(cmd)
		if len(tokens) < 2 {
			continue
		}
		mgr, ok := packageManager(tokens[0])
		if !ok {
			continue
		}
		if !isInstall(mgr, tokens[1]) {
			continue
		}
		// Walk remaining tokens; flags start with '-', pkg=ver pairs contain '='.
		for _, tok := range tokens[2:] {
			if strings.HasPrefix(tok, "-") {
				continue
			}
			eq := strings.Index(tok, "=")
			if eq < 0 {
				continue // unpinned — skip
			}
			pkg := tok[:eq]
			ver := tok[eq+1:]
			if pkg == "" || ver == "" {
				continue
			}
			offset := findVersionOffset(content, lineOffsets, instrLine, pkg, ver)
			pins = append(pins, Pin{
				Stage:      stage,
				Package:    pkg,
				Version:    ver,
				Line:       instrLine,
				ByteOffset: offset,
				Manager:    mgr,
				Status:     StatusUnknown,
			})
		}
	}
	return pins
}

// splitCommands splits a shell fragment on &&, ||, ;, and | operators.
func splitCommands(s string) []string {
	// Replace multi-char operators first so we can split on a single delimiter.
	s = strings.ReplaceAll(s, "&&", "\x00")
	s = strings.ReplaceAll(s, "||", "\x00")
	s = strings.ReplaceAll(s, ";", "\x00")
	s = strings.ReplaceAll(s, "|", "\x00")
	parts := strings.Split(s, "\x00")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// tokenise splits a command string into tokens by whitespace.
func tokenise(s string) []string {
	return strings.Fields(s)
}

// packageManager returns the normalised manager name ("apt" or "apk") and true
// if the command string is a recognised package manager binary.
func packageManager(cmd string) (string, bool) {
	switch cmd {
	case "apt-get", "apt":
		return "apt", true
	case "apk":
		return "apk", true
	}
	return "", false
}

// isInstall returns true when the subcommand is the install verb for the given manager.
func isInstall(mgr, sub string) bool {
	if mgr == "apt" {
		return sub == "install"
	}
	return sub == "add" // apk
}

// buildLineOffsets returns a slice where lineOffsets[i] is the byte offset of
// the start of line i+1 (1-indexed lines).
func buildLineOffsets(content []byte) []int {
	offsets := []int{0}
	for i, b := range content {
		if b == '\n' {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}

// findVersionOffset finds the byte offset of the version string within content,
// searching from instrLine (1-based) onwards. Returns -1 if not found.
func findVersionOffset(content []byte, lineOffsets []int, instrLine int, pkg, version string) int {
	pattern := []byte(pkg + "=" + version)
	startByte := 0
	if instrLine > 0 && instrLine-1 < len(lineOffsets) {
		startByte = lineOffsets[instrLine-1]
	}
	idx := bytes.Index(content[startByte:], pattern)
	if idx < 0 {
		return -1
	}
	return startByte + idx + len(pkg) + 1 // offset of the version string itself
}
