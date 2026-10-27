package pins

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/Arham1716/imgowner/internal/dockerfile"
)

// Extract parses all RUN instructions in the Dockerfile and returns one Pin per
// exact-pinned OS package found in apt-get/apt/apk/dnf/yum/microdnf install
// invocations (Story 2.1, FR-12). content is the raw Dockerfile bytes.
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
		thirdParty := detectThirdPartyRepos(&stage)
		vars := newStageVars(df.Args)

		for _, instr := range stage.Lines {
			switch strings.ToUpper(instr.Command) {
			case "ARG", "ENV":
				vars.record(instr)
				continue
			case "RUN":
			default:
				continue
			}
			found := extractFromRun(instr.Args, instr.Line, content, lineOffsets, stage.Name)
			for i := range found {
				found[i].StageIndex = stage.Index
				classifyPin(&found[i], vars, thirdParty, content, lineOffsets)
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

// stageVars tracks the ARG and ENV values in scope at each point of a stage,
// in Dockerfile order, so a pin sees only the variables defined above it.
type stageVars struct {
	values map[string]string // name -> value ("" = declared without a default)
}

func newStageVars(globalArgs map[string]string) *stageVars {
	v := &stageVars{values: make(map[string]string, len(globalArgs))}
	for k, val := range globalArgs {
		v.values[k] = val
	}
	return v
}

// record applies one ARG or ENV instruction. ENV accepts "KEY=VALUE ..." and
// the legacy "KEY VALUE" form; a stage ARG without a default keeps a global
// default (as `docker build` does).
func (v *stageVars) record(instr dockerfile.Instruction) {
	// The parser's Args for ENV is its own "KEY VALUE =" node rendering, so
	// read the instruction as written instead.
	args := strings.TrimSpace(instr.Raw)
	if kw, rest, ok := strings.Cut(args, " "); ok && strings.EqualFold(kw, instr.Command) {
		args = strings.TrimSpace(rest)
	} else {
		args = strings.TrimSpace(instr.Args)
	}
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return
	}
	if strings.EqualFold(instr.Command, "ENV") && !strings.Contains(fields[0], "=") {
		if k, val, ok := strings.Cut(args, " "); ok {
			v.values[strings.TrimSpace(k)] = unquote(strings.TrimSpace(val))
		}
		return
	}
	for _, field := range fields {
		k, val, hasDefault := strings.Cut(field, "=")
		if hasDefault {
			v.values[k] = unquote(val)
		} else if _, exists := v.values[k]; !exists {
			v.values[k] = ""
		}
	}
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// thirdPartyIndicators are the shell fragments that add a package source
// other than the image's own OS repositories (FR-14). The first match is
// reported to the user as the reason.
var thirdPartyIndicators = []string{
	"add-apt-repository",
	"apt-key add",
	"/etc/apt/sources.list",
	"sources.list.d",
	"signed-by=",
	"apk add --repository",
	"--repository ",
	"--repository=",
	"/etc/apk/repositories",
	"--repositories-file",
	"config-manager --add-repo",
	"yum-config-manager",
	"/etc/yum.repos.d",
	"--enablerepo",
	"--repofrompath",
}

// detectThirdPartyRepos returns the indicator found if the stage adds a
// package source of its own, or "" (best-effort heuristic): the image's OS
// repository can't tell us anything about such a package's versions.
func detectThirdPartyRepos(stage *dockerfile.Stage) string {
	for _, instr := range stage.Lines {
		if !strings.EqualFold(instr.Command, "RUN") {
			continue
		}
		lower := strings.ToLower(instr.Args)
		for _, indicator := range thirdPartyIndicators {
			if strings.Contains(lower, indicator) {
				return strings.TrimSpace(indicator)
			}
		}
	}
	return ""
}

// classifyPin resolves ARG/ENV-expanded versions (FR-13) and marks pins that
// can't be looked up: StatusVariable when the variable has no value, and
// StatusUnsupported when the stage adds a third-party source (FR-14). Both
// keep their status through lookup and are never edited.
func classifyPin(p *Pin, vars *stageVars, thirdParty string, content []byte, lineOffsets []int) {
	if name, ok := varRef(p.Version); ok {
		def := vars.values[name]
		if def == "" {
			p.Status = StatusVariable
			p.Note = "version comes from $" + name + ", which has no default; pass it at build time"
			p.ByteOffset = -1
			return
		}
		// The editable text is the variable's value on its ARG/ENV line, not
		// the "${VAR}" on the RUN line.
		p.Version = def
		p.ByteOffset = varValueOffset(content, lineOffsets, p.Line, name, def)
		p.Note = "version from $" + name
	}
	if thirdParty != "" {
		p.Status = StatusUnsupported
		p.Note = "stage adds a third-party package source (" + thirdParty + "); its versions can't be checked against the OS repository"
	}
}

// varRef reports whether s is exactly a variable reference ($VAR or ${VAR})
// and returns the name.
func varRef(s string) (string, bool) {
	if !strings.HasPrefix(s, "$") {
		return "", false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(s, "$"), "{"), "}")
	if !identRe.MatchString(name) {
		return "", false
	}
	return name, true
}

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// varValueOffset finds the byte offset of value in the nearest ARG or ENV
// line above runLine that assigns it to name ("NAME=value", quoted or not,
// or ENV's "NAME value"). It returns -1 when the definition isn't found,
// which makes PlanEdits leave the pin alone rather than edit a guess.
func varValueOffset(content []byte, lineOffsets []int, runLine int, name, value string) int {
	for line := runLine - 1; line >= 1 && line <= len(lineOffsets); line-- {
		start := lineOffsets[line-1]
		end := len(content)
		if line < len(lineOffsets) {
			end = lineOffsets[line]
		}
		text := content[start:end]
		trimmed := bytes.TrimLeft(text, " \t")
		upper := strings.ToUpper(string(trimmed[:min(4, len(trimmed))]))
		if !strings.HasPrefix(upper, "ARG ") && !strings.HasPrefix(upper, "ENV ") {
			continue
		}
		for _, form := range []string{name + "=" + value, name + `="` + value, name + "='" + value, name + " " + value} {
			if i := bytes.Index(text, []byte(form)); i >= 0 {
				// Make sure "NAME" isn't the tail of a longer name.
				if i > 0 && isIdentByte(text[i-1]) {
					continue
				}
				return start + i + len(form) - len(value)
			}
		}
	}
	return -1
}

func isIdentByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// extractFromRun tokenises a RUN instruction's argument string and returns
// any exact-pinned packages from package-manager install invocations.
func extractFromRun(runArgs string, instrLine int, content []byte, lineOffsets []int, stage string) []Pin {
	// Normalise line continuations and split into individual commands.
	normalised := strings.ReplaceAll(runArgs, "\\\n", " ")
	cmds := splitCommands(normalised)

	var pins []Pin
	for _, cmd := range cmds {
		mgr, pkgs, ok := installArgs(tokenise(cmd))
		if !ok {
			continue
		}
		for _, tok := range pkgs {
			var pkg, ver string
			if mgr == "rpm" {
				var ok bool
				if pkg, ver, ok = splitRPMToken(tok); !ok {
					continue // unpinned — skip
				}
			} else {
				var ok bool
				if pkg, ver, ok = strings.Cut(tok, "="); !ok {
					continue // unpinned — skip
				}
			}
			// A glob ("curl=7.88*") or an empty side is not an exact pin.
			if pkg == "" || ver == "" || strings.ContainsAny(ver, "*?") {
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

// managerSyntax describes one package manager's command line: its install
// verb and the options that take a separate value ("-o x", "--virtual x"),
// so that value is never mistaken for the verb or a package.
type managerSyntax struct {
	mgr        string
	verb       string
	valueFlags map[string]bool
}

var syntaxes = map[string]managerSyntax{
	"apt-get": {"apt", "install", set("-o", "--option", "-t", "--target-release", "-c", "--config-file")},
	"apt":     {"apt", "install", set("-o", "--option", "-t", "--target-release", "-c", "--config-file")},
	"apk": {"apk", "add", set("-X", "--repository", "-p", "--root", "--arch", "--keys-dir",
		"--repositories-file", "-t", "--virtual", "--cache-dir")},
	"dnf": {"rpm", "install", set("-c", "--config", "--repo", "--repoid", "--enablerepo", "--disablerepo",
		"--releasever", "--installroot", "-x", "--exclude", "--setopt")},
	"yum": {"rpm", "install", set("-c", "--config", "--enablerepo", "--disablerepo", "--releasever",
		"--installroot", "-x", "--exclude", "--setopt")},
	"microdnf": {"rpm", "install", set("--enablerepo", "--disablerepo", "--releasever", "--installroot", "--setopt")},
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

// installArgs recognises "<manager> [options] <install-verb> [options|packages]",
// optionally behind environment assignments (DEBIAN_FRONTEND=noninteractive),
// env or sudo, and returns the manager and the package tokens. Options may
// come before the verb (apt-get -y install, apk --no-cache add) and
// value-taking options consume their value.
func installArgs(tokens []string) (mgr string, pkgs []string, ok bool) {
	i := 0
	for i < len(tokens) && (isAssignment(tokens[i]) || tokens[i] == "env" || tokens[i] == "sudo") {
		i++
	}
	if i >= len(tokens) {
		return "", nil, false
	}
	syn, known := syntaxes[tokens[i]]
	if !known {
		return "", nil, false
	}
	i++
	// Options before the verb.
	for i < len(tokens) && strings.HasPrefix(tokens[i], "-") {
		if syn.valueFlags[tokens[i]] {
			i++
		}
		i++
	}
	if i >= len(tokens) || tokens[i] != syn.verb {
		return "", nil, false
	}
	i++
	for ; i < len(tokens); i++ {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			if syn.valueFlags[t] {
				i++ // skip the option's value (e.g. apk add --virtual .build-deps)
			}
			continue
		}
		pkgs = append(pkgs, unquote(t))
	}
	return syn.mgr, pkgs, true
}

// isAssignment reports whether tok is a shell variable assignment (NAME=value).
func isAssignment(tok string) bool {
	name, _, ok := strings.Cut(tok, "=")
	return ok && identRe.MatchString(name)
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

// splitRPMToken splits an RPM pin into name and version, e.g.
// "curl-7.76.1-26.el9" into ("curl", "7.76.1-26.el9").
//
// Names may themselves contain dashes and digits ("ca-certificates",
// "java-17-openjdk-headless", "gcc-toolset-12-runtime"), so the split works
// from the right, the way rpm reads name-version-release:
//
//   - name-version-release: the last segment (release) contains a digit and
//     the one before it (version) starts with a digit;
//   - name-version (dnf accepts it): the last segment starts with a digit
//     and contains a '.' or ':' (so "lib32-2" stays a name);
//
// anything else is an unpinned package name. Splitting at the first
// "dash + digit" instead turned "java-17-openjdk-headless" into package
// "java" pinned at "17-openjdk-headless".
func splitRPMToken(tok string) (pkg, version string, ok bool) {
	segs := strings.Split(tok, "-")
	n := len(segs)
	if n >= 3 && strings.ContainsAny(segs[n-1], "0123456789") && startsWithDigit(segs[n-2]) {
		pkg = strings.Join(segs[:n-2], "-")
		return pkg, segs[n-2] + "-" + segs[n-1], pkg != ""
	}
	if n >= 2 && startsWithDigit(segs[n-1]) && strings.ContainsAny(segs[n-1], ".:") {
		pkg = strings.Join(segs[:n-1], "-")
		return pkg, segs[n-1], pkg != ""
	}
	return "", "", false
}

func startsWithDigit(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }

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
