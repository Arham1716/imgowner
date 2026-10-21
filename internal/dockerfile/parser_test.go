package dockerfile

import "testing"

func TestParseBytes_SingleStage(t *testing.T) {
	src := `FROM debian:12-slim
RUN apt-get update
COPY . /app
`
	f, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if len(f.Stages) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(f.Stages))
	}
	s := f.Stages[0]
	if s.BaseRef != "debian:12-slim" {
		t.Errorf("BaseRef: want debian:12-slim, got %s", s.BaseRef)
	}
	if s.Name != "" {
		t.Errorf("unnamed stage should have empty Name, got %q", s.Name)
	}
	// FROM, RUN, COPY.
	if len(s.Lines) != 3 {
		t.Fatalf("expected 3 instructions, got %d: %+v", len(s.Lines), s.Lines)
	}
}

func TestParseBytes_NamedMultiStage(t *testing.T) {
	src := `FROM golang:1.23 AS builder
RUN go build -o app .

FROM debian:12-slim AS final
COPY --from=builder /app /app
`
	f, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if len(f.Stages) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(f.Stages))
	}
	if f.Stages[0].Name != "builder" {
		t.Errorf("stage 0 name: want builder, got %q", f.Stages[0].Name)
	}
	if f.Stages[0].BaseRef != "golang:1.23" {
		t.Errorf("stage 0 base: want golang:1.23, got %q", f.Stages[0].BaseRef)
	}
	if f.Stages[1].Name != "final" {
		t.Errorf("stage 1 name: want final, got %q", f.Stages[1].Name)
	}
	if f.Stages[1].Index != 1 {
		t.Errorf("stage 1 index: want 1, got %d", f.Stages[1].Index)
	}
}

func TestFinalStage(t *testing.T) {
	src := `FROM a AS one
FROM b AS two
FROM c AS three
`
	f, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	final := f.FinalStage()
	if final == nil || final.Name != "three" {
		t.Fatalf("FinalStage: want 'three', got %+v", final)
	}
}

func TestFinalStage_NoStages(t *testing.T) {
	f := &File{}
	if got := f.FinalStage(); got != nil {
		t.Errorf("FinalStage on an empty file should return nil, got %+v", got)
	}
}

// Instructions issued before the first FROM — most commonly a global ARG used
// in the base image reference — must not be silently dropped. They belong to
// no stage, which is exactly why global ARGs are tracked separately.
func TestParseBytes_GlobalARGBeforeFrom(t *testing.T) {
	src := `ARG BASE_TAG=12-slim
FROM debian:${BASE_TAG}
RUN echo hi
`
	f, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if f.Args["BASE_TAG"] != "12-slim" {
		t.Errorf("global ARG default not captured: got %v", f.Args)
	}
	if len(f.Stages) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(f.Stages))
	}
}

func TestResolveBaseRef_SubstitutesGlobalARG(t *testing.T) {
	src := `ARG BASE_TAG=12-slim
FROM debian:${BASE_TAG}
`
	f, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	got := f.ResolveBaseRef(&f.Stages[0])
	if got != "debian:12-slim" {
		t.Errorf("ResolveBaseRef: want debian:12-slim, got %s", got)
	}
}

// The unbraced $VAR form is valid Dockerfile syntax alongside ${VAR} and must
// resolve identically.
func TestResolveBaseRef_UnbracedForm(t *testing.T) {
	src := `ARG BASE_TAG=12-slim
FROM debian:$BASE_TAG
`
	f, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	got := f.ResolveBaseRef(&f.Stages[0])
	if got != "debian:12-slim" {
		t.Errorf("ResolveBaseRef: want debian:12-slim, got %s", got)
	}
}

// An ARG with no default leaves the reference unresolved; ResolveBaseRef must
// not fabricate a value, since image.ResolveBase needs to detect this and
// report unattributed rather than resolve a bogus ref.
func TestResolveBaseRef_NoDefaultLeavesPlaceholder(t *testing.T) {
	src := `ARG BASE_TAG
FROM debian:${BASE_TAG}
`
	f, err := ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	got := f.ResolveBaseRef(&f.Stages[0])
	if got == "debian:" {
		t.Error("an ARG with no default must not resolve to an empty substitution")
	}
}

func TestParseARG(t *testing.T) {
	cases := []struct {
		in         string
		key, value string
		hasDefault bool
	}{
		{"FOO=bar", "FOO", "bar", true},
		{"FOO", "FOO", "", false},
		{"FOO=", "FOO", "", true}, // explicit empty default is still "has a default"
		{"  FOO = bar  ", "FOO", "bar", true},
	}
	for _, tc := range cases {
		k, v, ok := parseARG(tc.in)
		if k != tc.key || v != tc.value || ok != tc.hasDefault {
			t.Errorf("parseARG(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.in, k, v, ok, tc.key, tc.value, tc.hasDefault)
		}
	}
}

// The low-level tokenizer only groups lines into instruction/argument pairs;
// it does not validate that the instruction name is a real Dockerfile
// directive (that happens in a dispatch layer this package does not use), so
// unrecognised words do not error here. An unterminated heredoc does, since it
// breaks line-continuation parsing itself.
func TestParseBytes_UnterminatedHeredocErrors(t *testing.T) {
	_, err := ParseBytes([]byte("FROM debian:12-slim\nRUN <<EOF\necho hi\n"))
	if err == nil {
		t.Error("expected an error for an unterminated heredoc, got nil")
	}
}

// Matches real `docker build`, which also rejects a Dockerfile with no
// instructions at all.
func TestParseBytes_EmptyInputErrors(t *testing.T) {
	_, err := ParseBytes([]byte(""))
	if err == nil {
		t.Error("expected an error for an empty Dockerfile (no instructions), got nil")
	}
}
