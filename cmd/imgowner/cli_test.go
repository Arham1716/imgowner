package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// cliBinary is built once per test run: exit codes and stderr are decided in
// main(), so they can only be checked against a real process.
var cliBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "imgowner-cli-*")
	if err != nil {
		panic(err)
	}
	cliBinary = filepath.Join(dir, "imgowner")
	if runtime.GOOS == "windows" {
		cliBinary += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", cliBinary, ".").CombinedOutput(); err != nil {
		panic("building imgowner for CLI tests: " + err.Error() + "\n" + string(out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// cli runs the binary in a temp dir holding a minimal Dockerfile and returns
// the exit code and stderr.
func cli(t *testing.T, args ...string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine:3.20\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cliBinary, args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), stderr.String()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, stderr.String()
}

func writeCfg(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The acceptance run found these exiting 2 with an empty stderr, or 0.
func TestCLI_UsageErrorsExplainThemselves(t *testing.T) {
	for name, args := range map[string][]string{
		"unknown flag":           {"attribute", "--bogus"},
		"unknown command":        {"frobnicate"},
		"unknown pins command":   {"pins", "frobnicate"},
		"missing --image":        {"attribute"},
		"explicit config absent": {"--config", "does-not-exist.yaml", "attribute", "--image", "alpine:3.20"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stderr := cli(t, args...)
			if code != 2 {
				t.Errorf("exit %d, want 2", code)
			}
			if strings.TrimSpace(stderr) == "" {
				t.Error("nothing on stderr")
			}
		})
	}
}

// FR-29: unknown keys and invalid values are structured JSON, reported once.
func TestCLI_ConfigErrorsAreStructuredJSON(t *testing.T) {
	for name, c := range map[string]struct{ yaml, wantErr, wantKey string }{
		"unknown key":      {"scan:\n  platfrom: linux/amd64\n", "unknown config key", "scan.platfrom"},
		"misspelt fail_on": {"policy:\n  fail_on: [CRITICLA]\n", "invalid config", "policy.fail_on"},
		"bad timeout":      {"scan:\n  timeout: banana\n", "invalid config", "scan.timeout"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stderr := cli(t, "--config", writeCfg(t, c.yaml), "attribute", "--image", "alpine:3.20")
			if code != 2 {
				t.Fatalf("exit %d, want 2 (stderr %q)", code, stderr)
			}
			lines := strings.Split(strings.TrimSpace(stderr), "\n")
			if len(lines) != 1 {
				t.Fatalf("want exactly one JSON line on stderr, got %q", stderr)
			}
			var got map[string]string
			if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
				t.Fatalf("stderr is not JSON: %q", stderr)
			}
			if got["error"] != c.wantErr || got["key"] != c.wantKey {
				t.Errorf("got %v, want error=%q key=%q", got, c.wantErr, c.wantKey)
			}
		})
	}
}

func TestCLI_PinsWithoutSubcommandShowsHelp(t *testing.T) {
	if code, _ := cli(t, "pins"); code != 0 {
		t.Errorf("`imgowner pins` exit %d, want 0 (help)", code)
	}
}
