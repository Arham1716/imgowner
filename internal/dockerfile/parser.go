package dockerfile

import (
	"fmt"
	"strings"

	"github.com/Arham1716/imgowner/internal/safeio"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// Stage represents one Dockerfile stage (FROM ... AS name).
type Stage struct {
	Name    string // alias from AS clause, or "" for unnamed stages
	BaseRef string // raw FROM argument (may contain ARG references)
	Index   int    // stage index (0-based)
	Lines   []Instruction
}

// Instruction is a single Dockerfile directive with its line number.
type Instruction struct {
	Line    int
	Command string // uppercased directive, e.g. RUN, COPY, ENV
	Args    string // everything after the command keyword
	Raw     string // original line text
}

// File holds the parsed result of a Dockerfile.
type File struct {
	Stages []Stage
	Args   map[string]string // global ARG defaults
}

// FinalStage returns the last stage in the Dockerfile.
func (f *File) FinalStage() *Stage {
	if len(f.Stages) == 0 {
		return nil
	}
	return &f.Stages[len(f.Stages)-1]
}

// Parse reads and parses the Dockerfile at path.
func Parse(path string) (*File, error) {
	data, err := safeio.ReadFile(path, safeio.MaxDockerfile)
	if err != nil {
		return nil, fmt.Errorf("imgowner: reading dockerfile %s: %w", path, err)
	}
	return ParseBytes(data)
}

// ParseBytes parses Dockerfile content from a byte slice.
func ParseBytes(data []byte) (*File, error) {
	if len(data) > safeio.MaxDockerfile {
		return nil, &safeio.TooLargeError{What: "dockerfile", Limit: safeio.MaxDockerfile}
	}
	result, err := parser.Parse(strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("imgowner: parsing dockerfile: %w", err)
	}

	f := &File{Args: make(map[string]string)}
	var currentStage *Stage

	for _, child := range result.AST.Children {
		cmd := strings.ToUpper(child.Value)
		args := joinArgs(child.Next)
		instr := Instruction{
			Line:    child.StartLine,
			Command: cmd,
			Args:    args,
			Raw:     child.Original,
		}

		switch cmd {
		case "FROM":
			stage := Stage{
				Index:   len(f.Stages),
				BaseRef: args,
			}
			// Parse "image AS name"
			parts := strings.Fields(args)
			if len(parts) >= 3 && strings.ToUpper(parts[1]) == "AS" {
				stage.Name = strings.ToLower(parts[2])
				stage.BaseRef = parts[0]
			}
			f.Stages = append(f.Stages, stage)
			currentStage = &f.Stages[len(f.Stages)-1]
			currentStage.Lines = append(currentStage.Lines, instr)

		case "ARG":
			// Collect global ARG defaults (before first FROM).
			if currentStage == nil {
				if k, v, ok := parseARG(args); ok {
					f.Args[k] = v
				}
			} else {
				currentStage.Lines = append(currentStage.Lines, instr)
			}

		default:
			if currentStage != nil {
				currentStage.Lines = append(currentStage.Lines, instr)
			}
		}
	}

	return f, nil
}

// ResolveBaseRef substitutes ARG variables in the FROM argument using the
// global ARG defaults collected during parsing.
func (f *File) ResolveBaseRef(stage *Stage) string {
	ref := f.substituteArgs(stage.BaseRef)

	// A multi-stage build's FROM can name an earlier stage instead of an
	// external image ("FROM base AS app" referencing an earlier
	// "... AS base"). Docker resolves that by stage name, not as a registry
	// pull, so follow the chain to the ultimate external image: the one FR-04
	// actually needs to diff layers against. Bounded by len(Stages)+1 so a
	// malformed file can't loop forever; a real Dockerfile can only reference
	// stages defined earlier than itself, so no cycle is reachable here.
	for i := 0; i <= len(f.Stages); i++ {
		next, ok := f.stageRefByName(ref)
		if !ok {
			return ref
		}
		ref = f.substituteArgs(next)
	}
	return ref
}

func (f *File) substituteArgs(ref string) string {
	for k, v := range f.Args {
		ref = strings.ReplaceAll(ref, "${"+k+"}", v)
		ref = strings.ReplaceAll(ref, "$"+k, v)
	}
	return ref
}

// stageRefByName returns the BaseRef of the stage named name (matched the way
// Docker matches a FROM target against an AS alias), if one exists.
func (f *File) stageRefByName(name string) (string, bool) {
	for i := range f.Stages {
		if f.Stages[i].Name != "" && strings.EqualFold(f.Stages[i].Name, name) {
			return f.Stages[i].BaseRef, true
		}
	}
	return "", false
}

// joinArgs reconstructs an instruction's argument string from the parser's
// node chain. Simple instructions such as FROM tokenise each word into its own
// chained node ("golang:1.23" -> "AS" -> "builder"), while shell-form
// instructions such as RUN keep their entire remainder in a single node; both
// cases are handled correctly by joining whatever nodes are present.
func joinArgs(n *parser.Node) string {
	var words []string
	for ; n != nil; n = n.Next {
		words = append(words, n.Value)
	}
	return strings.Join(words, " ")
}

// parseARG splits "KEY=VALUE" or "KEY" into key and optional value.
func parseARG(s string) (key, value string, hasDefault bool) {
	if idx := strings.IndexByte(s, '='); idx >= 0 {
		return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+1:]), true
	}
	return strings.TrimSpace(s), "", false
}
