package pins

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTools puts executable stubs on PATH for a shell running a lookup script.
func fakeTools(t *testing.T, tools map[string]string) []string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range tools {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func runScript(t *testing.T, mgr string, env []string) (string, error) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh available")
	}
	script, err := buildLookupScript(mgr, []Pin{{Package: "curl", Version: "1.0"}})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, "-c", script)
	cmd.Env = env
	out, err := cmd.Output()
	return string(out), err
}

// A failed index refresh used to be invisible: "apt-get update ... 2>/dev/null;"
// carried on, "apt-cache madison" came back empty, and the pin was reported
// UNAVAILABLE -- a claim that the package is gone from the repository, made
// when the network had merely failed. Run the real generated script with a
// package manager whose refresh always fails.
func TestLookupScript_FailedIndexRefreshIsReportedAsFailureNotUnavailable(t *testing.T) {
	for _, c := range []struct{ mgr, tool string }{{"apt", "apt-get"}, {"apk", "apk"}, {"rpm", "dnf"}} {
		t.Run(c.mgr, func(t *testing.T) {
			out, err := runScript(t, c.mgr, fakeTools(t, map[string]string{c.tool: "exit 1"}))
			if err != nil {
				t.Fatalf("the script must exit 0 and report the failure on stdout, got %v", err)
			}
			if strings.Contains(out, "UNAVAILABLE") {
				t.Fatalf("a failed refresh was reported as UNAVAILABLE: %s", out)
			}
			if _, failed := lookupFailure([]byte(out)); !failed {
				t.Fatalf("the failed refresh was not reported as a failure: %q", out)
			}
		})
	}
}

// An absent package is still UNAVAILABLE once the index did refresh: only the
// refresh failure is reclassified.
func TestLookupScript_AbsentPackageIsStillUnavailableWhenTheIndexRefreshed(t *testing.T) {
	env := fakeTools(t, map[string]string{
		"apt-get":   "exit 0", // the refresh succeeds
		"apt-cache": "exit 0", // ...and finds nothing
	})
	out, err := runScript(t, "apt", env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "UNAVAILABLE|curl") {
		t.Errorf("a package missing from a refreshed index must stay UNAVAILABLE, got %q", out)
	}
}

func TestFinishLookup_ReportsAFailedRefreshAsALookupFailureAndLeavesPinsUnknown(t *testing.T) {
	pins := []Pin{
		{Package: "curl", Version: "1.0", Status: StatusUnknown},
		{Package: "git", Version: "2.0", Status: StatusUnknown},
	}
	got, err := finishLookup("debian:12", RuntimeDocker, pins,
		[]byte("FAILED|apt-get update could not refresh the package index\n"))
	var lf *LookupFailedError
	if !errors.As(err, &lf) {
		t.Fatalf("expected *LookupFailedError, got %v", err)
	}
	if !strings.Contains(lf.Detail, "refresh") {
		t.Errorf("the detail should explain the failure, got %q", lf.Detail)
	}
	for _, p := range got {
		if p.Status != StatusUnknown {
			t.Errorf("%s: status %s, want unknown", p.Package, p.Status)
		}
	}
}

func TestFinishLookup_NormalOutputIsUnchanged(t *testing.T) {
	pins := []Pin{{Package: "curl", Version: "1.0", Status: StatusUnknown}}
	got, err := finishLookup("debian:12", RuntimeDocker, pins, []byte("UPDATE|curl|1.0|1.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Status != StatusUpdateAvailable || got[0].Available != "1.1" {
		t.Errorf("got %s/%q", got[0].Status, got[0].Available)
	}
}
