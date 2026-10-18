package pins

import (
	"strings"
	"testing"

	"github.com/Arham1716/imgowner/internal/dockerfile"
)

func TestExtract_AptGet(t *testing.T) {
	src := `FROM debian:12-slim
RUN apt-get update && apt-get install -y curl=7.88.1-10 openssl=3.0.11-1~deb12u1
`
	df, err := dockerfile.ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	pins, err := Extract([]byte(src), df)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	want := map[string]string{
		"curl":    "7.88.1-10",
		"openssl": "3.0.11-1~deb12u1",
	}
	if len(pins) != len(want) {
		t.Fatalf("expected %d pins, got %d: %+v", len(want), len(pins), pins)
	}
	for _, p := range pins {
		expected, ok := want[p.Package]
		if !ok {
			t.Errorf("unexpected package: %s", p.Package)
			continue
		}
		if p.Version != expected {
			t.Errorf("package %s: expected version %q, got %q", p.Package, expected, p.Version)
		}
		if p.Manager != "apt" {
			t.Errorf("package %s: expected manager apt, got %s", p.Package, p.Manager)
		}
		if p.ByteOffset < 0 {
			t.Errorf("package %s: expected non-negative byte offset", p.Package)
		}
	}
}

func TestExtract_Apk(t *testing.T) {
	src := `FROM alpine:3.20
RUN apk add --no-cache curl=8.9.1-r0 busybox=1.36.1-r29
`
	df, err := dockerfile.ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	pins, err := Extract([]byte(src), df)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	want := map[string]string{
		"curl":    "8.9.1-r0",
		"busybox": "1.36.1-r29",
	}
	if len(pins) != len(want) {
		t.Fatalf("expected %d pins, got %d: %+v", len(want), len(pins), pins)
	}
	for _, p := range pins {
		expected, ok := want[p.Package]
		if !ok {
			t.Errorf("unexpected package: %s", p.Package)
			continue
		}
		if p.Version != expected {
			t.Errorf("package %s: expected version %q, got %q", p.Package, expected, p.Version)
		}
		if p.Manager != "apk" {
			t.Errorf("package %s: expected manager apk, got %s", p.Package, p.Manager)
		}
	}
}

func TestExtract_UnpinnedIgnored(t *testing.T) {
	src := `FROM debian:12-slim
RUN apt-get install -y curl wget ca-certificates
`
	df, err := dockerfile.ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	pins, err := Extract([]byte(src), df)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(pins) != 0 {
		t.Errorf("expected 0 pins for unpinned packages, got %d", len(pins))
	}
}

func TestExtract_ByteOffset(t *testing.T) {
	src := "FROM debian:12-slim\nRUN apt-get install -y curl=7.88.1-10\n"
	df, err := dockerfile.ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	pins, err := Extract([]byte(src), df)
	if err != nil || len(pins) != 1 {
		t.Fatalf("extract: %v, pins: %v", err, pins)
	}

	p := pins[0]
	// The byte at ByteOffset should be the start of the version string.
	versionInFile := string([]byte(src)[p.ByteOffset : p.ByteOffset+len(p.Version)])
	if versionInFile != p.Version {
		t.Errorf("ByteOffset %d: got %q, want %q", p.ByteOffset, versionInFile, p.Version)
	}
}

func TestBuildLookupScript_Apt(t *testing.T) {
	pins := []Pin{
		{Package: "curl", Version: "7.88.1-10", Manager: "apt"},
	}
	script, err := buildLookupScript("apt", pins)
	if err != nil {
		t.Fatalf("buildLookupScript: %v", err)
	}
	if !strings.Contains(script, "apt-cache madison") {
		t.Errorf("expected apt-cache madison in script; got: %s", script)
	}
	if !strings.Contains(script, "curl") {
		t.Errorf("expected package name 'curl' in script; got: %s", script)
	}
}

func TestBuildLookupScript_Apk(t *testing.T) {
	pins := []Pin{
		{Package: "curl", Version: "8.9.1-r0", Manager: "apk"},
	}
	script, err := buildLookupScript("apk", pins)
	if err != nil {
		t.Fatalf("buildLookupScript: %v", err)
	}
	if !strings.Contains(script, "apk search") {
		t.Errorf("expected 'apk search' in script; got: %s", script)
	}
}

func TestSanitizeIdentifier(t *testing.T) {
	cases := []struct{ in, want string }{
		{"curl", "curl"},
		{"libssl-dev", "libssl-dev"},
		{"pkg; rm -rf /", "pkgrm-rf"},
		{"ca-certificates", "ca-certificates"},
	}
	for _, c := range cases {
		got := sanitizeIdentifier(c.in)
		if got != c.want {
			t.Errorf("sanitizeIdentifier(%q): want %q got %q", c.in, c.want, got)
		}
	}
}

func TestExtract_VariablePin_NoDefault(t *testing.T) {
	src := `FROM debian:12-slim
ARG CURL_VER
RUN apt-get install -y curl=${CURL_VER}
`
	df, err := dockerfile.ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pins, err := Extract([]byte(src), df)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("expected 1 pin, got %d", len(pins))
	}
	if pins[0].Status != StatusVariable {
		t.Errorf("expected StatusVariable, got %s", pins[0].Status)
	}
}

func TestExtract_VariablePin_WithDefault(t *testing.T) {
	src := `FROM debian:12-slim
ARG CURL_VER=7.88.1-10
RUN apt-get install -y curl=${CURL_VER}
`
	df, err := dockerfile.ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pins, err := Extract([]byte(src), df)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("expected 1 pin, got %d", len(pins))
	}
	if pins[0].Status == StatusVariable {
		t.Error("expected resolved pin (has default), got StatusVariable")
	}
	if pins[0].Version != "7.88.1-10" {
		t.Errorf("expected resolved version 7.88.1-10, got %s", pins[0].Version)
	}
}

func TestExtract_ThirdPartyRepo(t *testing.T) {
	src := `FROM debian:12-slim
RUN curl -fsSL https://example.com/key.gpg | apt-key add - && \
    echo "deb https://example.com/apt stable main" > /etc/apt/sources.list.d/custom.list
RUN apt-get update && apt-get install -y custom-pkg=1.2.3
`
	df, err := dockerfile.ParseBytes([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pins, err := Extract([]byte(src), df)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("expected 1 pin, got %d: %+v", len(pins), pins)
	}
	if pins[0].Status != StatusUnsupported {
		t.Errorf("expected StatusUnsupported for third-party repo package, got %s", pins[0].Status)
	}
}

func TestApplyCVEFixes(t *testing.T) {
	pins := []Pin{
		{Package: "curl", Status: StatusUpdateAvailable},
		{Package: "openssl", Status: StatusCurrent},
	}
	fixMap := map[string][]string{
		"curl": {"CVE-2024-1234"},
	}
	result := ApplyCVEFixes(pins, fixMap)

	if result[0].Status != StatusFixesCVEs {
		t.Errorf("curl: expected StatusFixesCVEs, got %s", result[0].Status)
	}
	if len(result[0].FixesCVEs) != 1 || result[0].FixesCVEs[0] != "CVE-2024-1234" {
		t.Errorf("curl: expected FixesCVEs=[CVE-2024-1234], got %v", result[0].FixesCVEs)
	}
	if result[1].Status != StatusCurrent {
		t.Errorf("openssl: expected StatusCurrent unchanged, got %s", result[1].Status)
	}
}
