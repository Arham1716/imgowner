package pins

import (
	"bytes"
	"strings"

	"github.com/Arham1716/imgowner/internal/dockerfile"
)

// Extract parses all RUN instructions in the Dockerfile and returns one Pin per
// exact-pinned OS package found in apt-get/apt/apk install|add invocations
// (Story 2.1, FR-12). content is the raw Dockerfile bytes.
// ignorePackages is the list from config.Pins.IgnorePackages; matching pins
// are silently skipped.
func Extract(content []byte, df *dockerfile.File, ignorePackages ...string) ([]Pin, error) {
	ignoreSet := make(map[string]bool, len(ignorePackages))
	for _, p := range ignorePackages {
		ignoreSet[p] = true
	}
	lineOffsets := buildLineOffsets(content)
	var pins []Pin

	for _, stage := range df.Stages {
		// Collect stage-level ARG defaults (merged with global defaults).
		stageArgs := collectStageArgs(&stage, df.Args)
		thirdParty := detectThirdPartyRepos(&stage)

		for _, instr := range stage.Lines {
			if !strings.EqualFold(instr.Command, "RUN") {
				continue
			}
			found := extractFromRun(instr.Args, instr.Line, content, lineOffsets, stage.Name)
			for i := range found {
				classifyPin(&found[i], stageArgs, thirdParty)
			}
			for _, p := range found {
				if !ignoreSet[p.Package] {
					pins = append(pins, p)
				}
			}
		}
	}
	return pins, nil
}

// collectStageArgs merges global ARG defaults with any ARG instructions inside
// the stage itself. Stage-level ARGs shadow global ones.
func collectStageArgs(stage *dockerfile.Stage, globalArgs map[string]string) map[string]string {
	merged := make(map[string]string, len(globalArgs))
	for k, v := range globalArgs {
		merged[k] = v
	}
	for _, instr := range stage.Lines {
		if !strings.EqualFold(instr.Command, "ARG") {
			continue
		}
		if k, v, hasDefault := parseARGLine(instr.Args); hasDefault {
			merged[k] = v
		} else if _, exists := merged[k]; !exists {
			merged[k] = "" // no default
		}
	}
	return merged
}

// parseARGLine splits "KEY=VALUE" or "KEY" (mirrors dockerfile.parseARG).
func parseARGLine(s string) (key, value string, hasDefault bool) {
	if idx := strings.IndexByte(s, '='); idx >= 0 {
		return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+1:]), true
	}
	return strings.TrimSpace(s), "", false
}

// detectThirdPartyRepos returns true if the stage adds a custom apt/apk
// repository source before its install commands, marking all apt-pinned packages
// in that stage as potentially unsupported (best-effort heuristic).
func detectThirdPartyRepos(stage *dockerfile.Stage) bool {
	thirdParty3PIndicators := []string{
		"add-apt-repository",
		"apt-key add",
		"sources.list.d",
		"apk add --repository",
		"--repositories-file",
	}
	for _, instr := range stage.Lines {
		if !strings.EqualFold(instr.Command, "RUN") {
			continue
		}
		lower := strings.ToLower(instr.Args)
		for _, indicator := range thirdParty3PIndicators {
			if strings.Contains(lower, indicator) {
				return true
			}
		}
	}
	return false
}

// classifyPin sets StatusVariable or StatusUnsupported when applicable,
// and resolves ARG-expanded versions where a default exists.
func classifyPin(p *Pin, stageArgs map[string]string, thirdParty bool) {
	ver := p.Version
	if isARGRef(ver) {
		varName := argVarName(ver)
		if def, ok := stageArgs[varName]; ok && def != "" {
			// ARG has a default — resolve it so the version can be looked up.
			// The resolved text lives on the ARG line, not at the RUN-line
			// offset found for "${VAR}", so that offset no longer points at
			// p.Version. Left as is, ApplyEdits rejects the mismatch and the
			// whole pins update fails; -1 makes PlanEdits skip just this pin.
			p.Version = def
			p.ByteOffset = -1
		} else {
			// ARG-only with no default — cannot look up.
			p.Status = StatusVariable
		}
		return
	}
	if thirdParty {
		p.Status = StatusUnsupported
	}
}

// isARGRef returns true if the string is a shell variable reference like
// ${VAR} or $VAR.
func isARGRef(s string) bool {
	return strings.HasPrefix(s, "$")
}

// argVarName extracts the variable name from ${VAR} or $VAR.
func argVarName(s string) string {
	s = strings.TrimPrefix(s, "$")
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	return s
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
		// Walk remaining tokens; flags start with '-'. apt and apk pin with
		// "pkg=version"; rpm-family managers use "pkg-version-release".
		for _, tok := range tokens[2:] {
			if strings.HasPrefix(tok, "-") {
				continue
			}

			var pkg, ver string
			if mgr == "rpm" {
				var ok bool
				if pkg, ver, ok = splitRPMToken(tok); !ok {
					continue // unpinned — skip
				}
			} else {
				eq := strings.Index(tok, "=")
				if eq < 0 {
					continue // unpinned — skip
				}
				pkg, ver = tok[:eq], tok[eq+1:]
			}
			if pkg == "" || ver == "" {
				continue
			}

			offset := findVersionOffset(content, lineOffsets, instrLine, pkg, ver, mgr)
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

// packageManager returns the normalised manager name and true if the command
// string is a recognised package manager binary.
func packageManager(cmd string) (string, bool) {
	switch cmd {
	case "apt-get", "apt":
		return "apt", true
	case "apk":
		return "apk", true
	case "yum", "dnf", "microdnf":
		return "rpm", true
	}
	return "", false
}

// isInstall returns true when the subcommand is the install verb for the given manager.
func isInstall(mgr, sub string) bool {
	switch mgr {
	case "apt", "rpm":
		return sub == "install"
	case "apk":
		return sub == "add"
	}
	return false
}

// splitRPMToken splits an RPM name-version-release token such as
// "curl-7.76.1-26.el9" into ("curl", "7.76.1-26.el9").
//
// RPM separates the name from the version with a dash, and package names may
// themselves contain dashes ("ca-certificates-2023.2.60"). The convention is
// that the version begins at the first dash followed by a digit, which is what
// rpm's own name parsing relies on.
func splitRPMToken(tok string) (pkg, version string, ok bool) {
	for i := 0; i < len(tok)-1; i++ {
		if tok[i] != '-' {
			continue
		}
		if tok[i+1] >= '0' && tok[i+1] <= '9' {
			pkg, version = tok[:i], tok[i+1:]
			return pkg, version, pkg != "" && version != ""
		}
	}
	return "", "", false
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
// The separator depends on the manager: apt and apk use '=', rpm uses '-'.
func findVersionOffset(content []byte, lineOffsets []int, instrLine int, pkg, version, mgr string) int {
	sep := "="
	if mgr == "rpm" {
		sep = "-"
	}
	pattern := []byte(pkg + sep + version)
	startByte := 0
	if instrLine > 0 && instrLine-1 < len(lineOffsets) {
		startByte = lineOffsets[instrLine-1]
	}
	idx := bytes.Index(content[startByte:], pattern)
	if idx < 0 {
		return -1
	}
	return startByte + idx + len(pkg) + len(sep) // offset of the version string itself
}
