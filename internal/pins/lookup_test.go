package pins

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The runtime's stderr is the useful part of a lookup failure ("failed to
// connect to the docker API ..."); the Go error alone is only "exit status 1",
// which tells the user nothing about why every pin came back unknown.
func TestRunFailureDetail_PrefersProcessStderr(t *testing.T) {
	// The test binary rejects an unknown -test.* flag with a message on stderr
	// and a non-zero exit, giving a real *exec.ExitError without needing Docker.
	_, err := exec.Command(os.Args[0], "-test.definitely-not-a-flag").Output()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected an *exec.ExitError from the probe process, got %T: %v", err, err)
	}

	got := runFailureDetail(err)
	if !strings.Contains(got, "definitely-not-a-flag") {
		t.Errorf("detail should carry the process's stderr, got %q", got)
	}
	if got == err.Error() {
		t.Errorf("detail fell back to the bare Go error %q instead of stderr", got)
	}
}

func TestRunFailureDetail_FallsBackToErrorText(t *testing.T) {
	err := errors.New("exec: \"docker\": executable file not found")
	if got := runFailureDetail(err); got != err.Error() {
		t.Errorf("non-exit errors should pass through unchanged, got %q", got)
	}
}

func TestLookupFailedError_MessageNamesImageRuntimeAndCause(t *testing.T) {
	e := &LookupFailedError{Image: "python:3.12-slim", Runtime: "docker", Detail: "daemon not running"}
	msg := e.Error()
	for _, want := range []string{"python:3.12-slim", "docker", "daemon not running"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q missing %q", msg, want)
		}
	}
}
