package dockerfile

import (
	"fmt"
	"os"
	"strings"

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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("imgowner: reading dockerfile %s: %w", path, err)
	}
	return ParseBytes(data)
}

// ParseBytes parses Dockerfile content from a byte slice.
func ParseBytes(data []byte) (*File, error) {
	result, err := parser.Parse(strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("imgowner: parsing dockerfile: %w", err)
	}

	f := &File{Args: make(map[string]string)}
	var currentStage *Stage

	for _, child := range result.AST.Children {
		cmd := strings.ToUpper(child.Value)
		args := ""
		if child.Next != nil {
			args = child.Next.Value
		}
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
	ref := stage.BaseRef
	for k, v := range f.Args {
		ref = strings.ReplaceAll(ref, "${"+k+"}", v)
		ref = strings.ReplaceAll(ref, "$"+k, v)
	}
	return ref
}

// parseARG splits "KEY=VALUE" or "KEY" into key and optional value.
func parseARG(s string) (key, value string, hasDefault bool) {
	if idx := strings.IndexByte(s, '='); idx >= 0 {
		return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+1:]), true
	}
	return strings.TrimSpace(s), "", false
}
