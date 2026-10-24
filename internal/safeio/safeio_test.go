package safeio

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestReadAll_WithinLimit(t *testing.T) {
	got, err := ReadAll(strings.NewReader("hello"), 5, "input")
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

// One byte past the limit must fail, not be silently truncated: a truncated
// Trivy report would parse as a smaller, wrong result.
func TestReadAll_OneByteOverLimitFails(t *testing.T) {
	_, err := ReadAll(strings.NewReader("hello!"), 5, "input")
	if !IsTooLarge(err) {
		t.Fatalf("expected *TooLargeError, got %v", err)
	}
	if !strings.Contains(err.Error(), "input") || !strings.Contains(err.Error(), "5") {
		t.Errorf("error should name the input and the limit, got %q", err)
	}
}

func TestReadFile_EnforcesLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(path, []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(path, 1024); err != nil {
		t.Fatalf("file under the limit should read, got %v", err)
	}
	if _, err := ReadFile(path, 4); !IsTooLarge(err) {
		t.Fatalf("file over the limit should fail with TooLargeError, got %v", err)
	}
}

// Callers rely on os.IsNotExist to treat a missing optional file (the config)
// as "use defaults".
func TestReadFile_MissingFileIsNotExist(t *testing.T) {
	_, err := ReadFile(filepath.Join(t.TempDir(), "absent"), 1024)
	if !os.IsNotExist(err) {
		t.Fatalf("expected a not-exist error, got %v", err)
	}
}

// helperCommand re-runs this test binary as a child process that prints n
// bytes and exits with code, so Output can be tested without a shell.
func helperCommand(t *testing.T, n, code int, stderr string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(),
		"SAFEIO_HELPER=1",
		"SAFEIO_N="+strconv.Itoa(n),
		"SAFEIO_CODE="+strconv.Itoa(code),
		"SAFEIO_STDERR="+stderr,
	)
	return cmd
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("SAFEIO_HELPER") != "1" {
		return
	}
	n, _ := strconv.Atoi(os.Getenv("SAFEIO_N"))
	code, _ := strconv.Atoi(os.Getenv("SAFEIO_CODE"))
	_, _ = os.Stdout.Write([]byte(strings.Repeat("x", n)))
	_, _ = os.Stderr.Write([]byte(os.Getenv("SAFEIO_STDERR")))
	os.Exit(code)
}

func TestOutput_WithinLimit(t *testing.T) {
	out, err := Output(helperCommand(t, 100, 0, ""), 1000, "helper")
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if len(out) != 100 {
		t.Errorf("got %d bytes, want 100", len(out))
	}
}

func TestOutput_OverLimitFails(t *testing.T) {
	_, err := Output(helperCommand(t, 5000, 0, ""), 1000, "helper")
	if !IsTooLarge(err) {
		t.Fatalf("expected *TooLargeError, got %v", err)
	}
}

// pins.runFailureDetail and the Trivy runner read ExitError.Stderr; Output must
// keep that contract or every failure loses its explanation.
func TestOutput_ExitErrorCarriesStderr(t *testing.T) {
	_, err := Output(helperCommand(t, 0, 3, "daemon not running"), 1000, "helper")
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *exec.ExitError, got %T: %v", err, err)
	}
	if !strings.Contains(string(ee.Stderr), "daemon not running") {
		t.Errorf("ExitError.Stderr = %q, want it to contain the child's stderr", ee.Stderr)
	}
}

func TestOutput_RejectsPresetStdout(t *testing.T) {
	cmd := helperCommand(t, 0, 0, "")
	cmd.Stdout = os.Stdout
	if _, err := Output(cmd, 10, "helper"); err == nil {
		t.Fatal("expected an error when Stdout is already set")
	}
}
