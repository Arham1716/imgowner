package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".imgowner.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func TestLoad_MissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("a missing config file must not be an error, got: %v", err)
	}
	if !reflect.DeepEqual(cfg, Defaults()) {
		t.Error("missing config file should yield exactly Defaults()")
	}
}

func TestLoad_EmptyFileReturnsDefaults(t *testing.T) {
	path := writeConfig(t, "")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("an empty config file must not be an error, got: %v", err)
	}
	if !reflect.DeepEqual(cfg, Defaults()) {
		t.Error("empty config file should yield exactly Defaults()")
	}
}

// A key the user sets must win; a key they omit must keep its default rather
// than being zeroed out. This is the behaviour the whole precedence model
// (CLI flags > .imgowner.yaml > defaults) depends on.
func TestLoad_PartialOverridePreservesOtherDefaults(t *testing.T) {
	path := writeConfig(t, `
policy:
  fail_on: [CRITICAL]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Policy.FailOn) != 1 || cfg.Policy.FailOn[0] != "CRITICAL" {
		t.Errorf("fail_on should be overridden to [CRITICAL], got %v", cfg.Policy.FailOn)
	}
	// enforce_owners was not mentioned in the file, so it must still be the default.
	want := Defaults().Policy.EnforceOwners
	if !reflect.DeepEqual(cfg.Policy.EnforceOwners, want) {
		t.Errorf("enforce_owners should keep its default %v, got %v", want, cfg.Policy.EnforceOwners)
	}
	// Scan was not mentioned at all, so it must be completely untouched.
	// Scan has no slice fields, so a plain == comparison is valid here.
	if cfg.Scan != Defaults().Scan {
		t.Errorf("scan section should be untouched by a policy-only override, got %+v", cfg.Scan)
	}
}

// FR-29: an unknown top-level key is a configuration error, not a silently
// ignored typo.
func TestLoad_UnknownTopLevelKeyErrors(t *testing.T) {
	path := writeConfig(t, "scann:\n  platform: linux/amd64\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error for an unknown top-level key (scann), got nil")
	}
}

// The same rule must apply to a typo nested inside a known section, since
// that is the more common mistake in practice.
func TestLoad_UnknownNestedKeyErrors(t *testing.T) {
	path := writeConfig(t, "scan:\n  platfrom: linux/amd64\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error for an unknown nested key (platfrom), got nil")
	}
}

func TestLoad_MalformedYAMLErrors(t *testing.T) {
	path := writeConfig(t, "scan: [this is not a mapping")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error for malformed YAML, got nil")
	}
}

func TestLoad_UnreadableFileErrors(t *testing.T) {
	// A directory can be "stat"-ed but not read as a file.
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected an error when the config path is a directory, got nil")
	}
}

func TestScanTimeout(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want time.Duration
	}{
		{"valid duration", "15m", 15 * time.Minute},
		{"empty falls back to 10m", "", 10 * time.Minute},
		{"garbage falls back to 10m", "not-a-duration", 10 * time.Minute},
		{"zero falls back to 10m", "0s", 10 * time.Minute},
		{"negative falls back to 10m", "-5m", 10 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Scan{TimeoutStr: tc.in}
			if got := s.Timeout(); got != tc.want {
				t.Errorf("Scan{TimeoutStr:%q}.Timeout() = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestPinsLookupDuration(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want time.Duration
	}{
		{"valid duration", "2m", 2 * time.Minute},
		{"empty falls back to 5m", "", 5 * time.Minute},
		{"garbage falls back to 5m", "nonsense", 5 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Pins{LookupTimeout: tc.in}
			if got := p.LookupDuration(); got != tc.want {
				t.Errorf("Pins{LookupTimeout:%q}.LookupDuration() = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestDefaults_IsStableAcrossCalls(t *testing.T) {
	a, b := Defaults(), Defaults()
	if !reflect.DeepEqual(a, b) {
		t.Error("Defaults() must be deterministic")
	}
}
