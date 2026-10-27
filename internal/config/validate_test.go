package config

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Every value the v0.5.0 acceptance run showed being silently accepted must
// now be rejected, naming the key. A misspelt policy value is the dangerous
// one: it matched nothing, so the CI gate was quietly off.
func TestValidate_RejectsEveryBadValue(t *testing.T) {
	for key, yaml := range map[string]string{
		"version":                 "version: 2\n",
		"scan.timeout":            "scan:\n  timeout: banana\n",
		"scan.timeout (negative)": "scan:\n  timeout: -1m\n",
		"scan.platform":           "scan:\n  platform: linux\n",
		"scan.base_candidates":    "scan:\n  base_candidates: -1\n",
		"scan.trivy_min_version":  "scan:\n  trivy_min_version: latest\n",
		"policy.fail_on":          "policy:\n  fail_on: [CRITICLA]\n",
		"policy.enforce_owners":   "policy:\n  enforce_owners: [aded-os]\n",
		"pins.lookup_timeout":     "pins:\n  lookup_timeout: soon\n",
		"pins.runtime":            "pins:\n  runtime: lxc\n",
		"report.formats":          "report:\n  formats: [pdf]\n",
		"scm.provider":            "scm:\n  provider: gitlab\n",
		"history.retention_days":  "history:\n  retention_days: 0\n",
	} {
		t.Run(key, func(t *testing.T) {
			_, err := Load(writeConfig(t, yaml))
			var inv *ErrInvalidConfig
			if !errors.As(err, &inv) {
				t.Fatalf("want ErrInvalidConfig, got %v", err)
			}
			want, _, _ := strings.Cut(key, " ") // "scan.timeout (negative)" -> "scan.timeout"
			if inv.Key != want {
				t.Errorf("error names key %q, want %q", inv.Key, want)
			}
		})
	}
}

func TestValidate_AcceptsCaseInsensitivePolicyValues(t *testing.T) {
	cfg, err := Load(writeConfig(t, "policy:\n  fail_on: [critical, High]\n  enforce_owners: [APP]\n"))
	if err != nil {
		t.Fatalf("mixed-case policy values rejected: %v", err)
	}
	if len(cfg.Policy.FailOn) != 2 {
		t.Errorf("fail_on = %v", cfg.Policy.FailOn)
	}
}

func TestDefaults_AreValid(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatalf("built-in defaults fail validation: %v", err)
	}
}

// The example users copy must itself be valid.
func TestShippedExampleConfigIsValid(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	example := filepath.Join(filepath.Dir(file), "..", "..", "examples", "imgowner.yaml.example")
	if _, err := LoadRequired(example); err != nil {
		t.Fatalf("examples/imgowner.yaml.example does not load: %v", err)
	}
}

// FR-29: the error names the full key path, so the user finds the typo.
func TestLoad_UnknownKeyNamesTheFullPath(t *testing.T) {
	for yaml, want := range map[string]string{
		"scann:\n  platform: linux/amd64\n":            "scann",
		"version: 1\nscan:\n  platfrom: linux/amd64\n": "scan.platfrom",
		"policy:\n  fail_onn: [HIGH]\n":                "policy.fail_onn",
	} {
		_, err := Load(writeConfig(t, yaml))
		var uk *ErrUnknownKey
		if !errors.As(err, &uk) {
			t.Fatalf("%q: want ErrUnknownKey, got %v", yaml, err)
		}
		if uk.Key != want || uk.Line < 1 {
			t.Errorf("%q: got key %q line %d, want %q", yaml, uk.Key, uk.Line, want)
		}
	}
}

// A file the user named explicitly must exist; falling back to defaults
// would silently drop every policy they think is in force.
func TestLoadRequired_MissingFileIsAnError(t *testing.T) {
	if _, err := LoadRequired(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("LoadRequired accepted a missing file")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err != nil {
		t.Fatalf("Load (default path) must still accept a missing file: %v", err)
	}
}
