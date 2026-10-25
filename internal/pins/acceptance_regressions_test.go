package pins

import (
	"context"
	"testing"

	"github.com/Arham1716/imgowner/internal/dockerfile"
)

func extract(t *testing.T, src string) []Pin {
	t.Helper()
	df, err := dockerfile.ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pins, err := Extract([]byte(src), df)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	return pins
}

func byName(pins []Pin) map[string]Pin {
	m := map[string]Pin{}
	for _, p := range pins {
		m[p.Package] = p
	}
	return m
}

// Common install styles the v0.5.0 extractor missed because it required the
// verb to be the second token.
func TestExtract_CommonInstallStyles(t *testing.T) {
	got := byName(extract(t, `FROM debian:12
RUN apt-get -y install curl=7.88.1-10
RUN apt-get -qq install -y wget=1.21.3-1
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git=1:2.39.2-1
RUN apt-get -o Dpkg::Options::=--force-confold install -y vim=2:9.0
RUN apt-get install -y -t bookworm-backports less=590-2
RUN sudo apt-get install -y nano=7.2-1
FROM alpine:3.20
RUN apk --no-cache add jq=1.7.1-r0
RUN set -eux; apk add --no-cache --virtual .build-deps gcc=13.2.1-r0
RUN apk -X https://example.invalid/main add zlib=1.3.1-r1
FROM rockylinux:9
RUN dnf -y install tar-1.34-11.el9 && dnf --setopt=install_weak_deps=False install -y git-core-2.43.5-1.el9
`))
	want := map[string]string{
		"curl": "7.88.1-10", "wget": "1.21.3-1", "git": "1:2.39.2-1", "vim": "2:9.0",
		"less": "590-2", "nano": "7.2-1", "jq": "1.7.1-r0", "gcc": "13.2.1-r0", "zlib": "1.3.1-r1",
		"tar": "1.34-11.el9", "git-core": "2.43.5-1.el9",
	}
	for pkg, ver := range want {
		if got[pkg].Version != ver {
			t.Errorf("%s: got version %q, want %q", pkg, got[pkg].Version, ver)
		}
	}
	for _, notAPin := range []string{".build-deps", "bookworm-backports", "Dpkg::Options::"} {
		if _, ok := got[notAPin]; ok {
			t.Errorf("%q (an option value) was read as a package", notAPin)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d pins, want %d: %v", len(got), len(want), got)
	}
}

// Unpinned RPM names containing "-<digit>" were misread as pins: package
// "java" at "17-openjdk-headless", which pins update could then rewrite.
func TestSplitRPMToken_NamesWithDigits(t *testing.T) {
	for tok, want := range map[string][2]string{
		"java-17-openjdk-headless":                  {"", ""},
		"gcc-toolset-12-runtime":                    {"", ""},
		"lib32-2":                                   {"", ""},
		"java-17-openjdk-headless-17.0.9.0.9-2.el9": {"java-17-openjdk-headless", "17.0.9.0.9-2.el9"},
		"compat-openssl11-1.1.1k-4.el9_0":           {"compat-openssl11", "1.1.1k-4.el9_0"},
		"python3-3.9.18":                            {"python3", "3.9.18"},
		"tar-2:1.34-11.el9":                         {"tar", "2:1.34-11.el9"},
	} {
		pkg, ver, ok := splitRPMToken(tok)
		if want[0] == "" {
			if ok {
				t.Errorf("%q read as pin (%q, %q); it is an unpinned name", tok, pkg, ver)
			}
			continue
		}
		if !ok || pkg != want[0] || ver != want[1] {
			t.Errorf("splitRPMToken(%q) = (%q, %q, %v), want (%q, %q)", tok, pkg, ver, ok, want[0], want[1])
		}
	}
}

// FR-13: ENV values resolve like ARG defaults, and the edit lands on them.
func TestExtract_ENVResolvesAndIsEditable(t *testing.T) {
	src := "FROM debian:12\nENV CURL_VERSION=7.88.1-10\nRUN apt-get install -y curl=$CURL_VERSION\n"
	p := extract(t, src)[0]
	if p.Version != "7.88.1-10" || p.ByteOffset < 0 || src[p.ByteOffset:p.ByteOffset+len(p.Version)] != p.Version {
		t.Fatalf("ENV pin not resolved to an editable offset: %+v", p)
	}
}

// FR-13: no default -> variable, with a reason; FR-14: third-party source ->
// unsupported, naming the source. Neither may be edited.
func TestExtract_VariableAndUnsupportedCarryAReason(t *testing.T) {
	pins := byName(extract(t, `FROM debian:12
ARG V
RUN apt-get install -y curl=${V}
FROM debian:12
RUN echo "deb http://repo.example.invalid/ x main" > /etc/apt/sources.list.d/x.list && apt-get update && apt-get install -y foo=1.0
`))
	if v := pins["curl"]; v.Status != StatusVariable || v.Note == "" {
		t.Errorf("curl: %+v", v)
	}
	if u := pins["foo"]; u.Status != StatusUnsupported || u.Note == "" {
		t.Errorf("foo: %+v", u)
	}
	for _, p := range pins {
		p.Available = "9.9"
		if len(PlanEdits([]Pin{p})) != 0 {
			t.Errorf("%s (%s) would be edited", p.Package, p.Status)
		}
	}
}

// The acceptance run found a variable pin reported "current" and a
// third-party pin "update-available": lookup overwrote their status. They
// must not even be sent to the container.
func TestLookupVersions_LeavesUnlookupablePinsAlone(t *testing.T) {
	pins := []Pin{
		{Package: "curl", Version: "${V}", Status: StatusVariable, Manager: "apt"},
		{Package: "foo", Version: "1.0", Status: StatusUnsupported, Manager: "apt"},
	}
	got, err := LookupVersions(context.Background(), Runtime("definitely-not-a-runtime"), "debian:12", pins)
	if err != nil {
		t.Fatalf("no lookup should have run: %v", err)
	}
	if got[0].Status != StatusVariable || got[1].Status != StatusUnsupported {
		t.Errorf("statuses changed: %+v", got)
	}
}

// FR-16/18/19: the three ways a pin can be absent.
func TestParseLookupOutput_MissingVersusUnavailable(t *testing.T) {
	pins := []Pin{
		{Package: "a", Version: "1.0", Status: StatusUnknown},
		{Package: "b", Version: "1.0", Status: StatusUnknown},
		{Package: "c", Version: "1.0", Status: StatusUnknown},
	}
	got := parseLookupOutput([]byte("MISSING|a|1.0|1.2\nUNAVAILABLE|b\nUPDATE|c|1.0|1.1\n"), pins)
	if got[0].Status != StatusUnavailable || got[0].Available != "1.2" {
		t.Errorf("a (version gone, package there): %+v", got[0])
	}
	if got[1].Status != StatusUnavailable || got[1].Available != "" {
		t.Errorf("b (package gone): %+v", got[1])
	}
	if got[2].Status != StatusUpdateAvailable {
		t.Errorf("c: %+v", got[2])
	}
	// FR-18 bumps a; FR-19 leaves b alone.
	got[0].ByteOffset, got[1].ByteOffset, got[2].ByteOffset = 0, 10, 20
	edits := PlanEdits(got)
	if len(edits) != 2 || edits[0].NewVersion != "1.2" || edits[1].NewVersion != "1.1" {
		t.Errorf("edits = %+v", edits)
	}
}

// FR-15: unnamed stages are distinct stages, each looked up in its own image.
func TestExtract_RecordsStageIndex(t *testing.T) {
	pins := extract(t, "FROM debian:12\nRUN apt-get install -y a=1.0\nFROM ubuntu:24.04\nRUN apt-get install -y b=2.0\n")
	if len(pins) != 2 || pins[0].StageIndex != 0 || pins[1].StageIndex != 1 {
		t.Fatalf("stage indexes: %+v", pins)
	}
}
