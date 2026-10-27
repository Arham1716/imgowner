package scan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeTrivy puts a trivy stub on PATH. `trivy version` reports the DB time in
// $FAKE_DB_UPDATED (none when empty); every `trivy image` appends a line to
// the returned counter file and prints one vulnerability.
func fakeTrivy(t *testing.T) (counter string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stub")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	counter = filepath.Join(dir, "scans")
	script := `#!/bin/sh
if [ "$1" = version ]; then
  if [ -n "$FAKE_DB_UPDATED" ]; then
    echo '{"Version":"0.76.0","VulnerabilityDB":{"UpdatedAt":"'"$FAKE_DB_UPDATED"'"}}'
  else
    echo '{"Version":"0.76.0"}'
  fi
  exit 0
fi
echo scan >> "` + counter + `"
echo '{"SchemaVersion":2,"Results":[{"Target":"t","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"p","Severity":"HIGH"}]}]}'
`
	if err := os.WriteFile(filepath.Join(dir, "trivy"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return counter
}

func scans(t *testing.T, counter string) int {
	t.Helper()
	b, err := os.ReadFile(counter)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "scan")
}

func TestRunner_ReusesAScanOnlyWhileTheVulnerabilityDBIsUnchanged(t *testing.T) {
	withIsolatedCacheDir(t)
	counter := fakeTrivy(t)
	r := &Runner{TrivyVersion: "0.76.0", Platform: "linux/amd64"}
	ref, digest := "img@sha256:aaa", "sha256:aaa"

	t.Setenv("FAKE_DB_UPDATED", "2026-10-25T12:00:00Z")
	for i := 0; i < 2; i++ {
		res, err := r.Scan(context.Background(), ref, digest)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Results) != 1 {
			t.Fatalf("scan %d: unexpected result %+v", i, res)
		}
	}
	if n := scans(t, counter); n != 1 {
		t.Fatalf("same DB: trivy ran %d times, want 1 (second run from cache)", n)
	}

	t.Setenv("FAKE_DB_UPDATED", "2026-10-26T12:00:00Z")
	if _, err := r.Scan(context.Background(), ref, digest); err != nil {
		t.Fatal(err)
	}
	if n := scans(t, counter); n != 2 {
		t.Fatalf("after a DB update trivy ran %d times in total, want 2: the old result was replayed", n)
	}
}

// With no vulnerability DB reported, freshness can't be proven: always scan.
func TestRunner_WithoutADBStampAlwaysScans(t *testing.T) {
	withIsolatedCacheDir(t)
	counter := fakeTrivy(t)
	t.Setenv("FAKE_DB_UPDATED", "")
	r := &Runner{TrivyVersion: "0.76.0", Platform: "linux/amd64"}
	for i := 0; i < 2; i++ {
		if _, err := r.Scan(context.Background(), "img@sha256:bbb", "sha256:bbb"); err != nil {
			t.Fatal(err)
		}
	}
	if n := scans(t, counter); n != 2 {
		t.Fatalf("trivy ran %d times, want 2", n)
	}
}

// An unusable cache directory degrades to a fresh scan, never a failure and
// never a read from the unsafe location.
func TestRunner_AnUnsafeCacheDirFallsBackToAFreshScan(t *testing.T) {
	base := t.TempDir()
	old := userCacheDir
	userCacheDir = func() (string, error) { return base, nil }
	t.Cleanup(func() { userCacheDir = old })
	if err := os.WriteFile(filepath.Join(base, "imgowner"), nil, 0o600); err != nil { // a file where the dir should be
		t.Fatal(err)
	}
	counter := fakeTrivy(t)
	t.Setenv("FAKE_DB_UPDATED", "2026-10-25T12:00:00Z")
	r := &Runner{TrivyVersion: "0.76.0", Platform: "linux/amd64"}
	for i := 0; i < 2; i++ {
		if _, err := r.Scan(context.Background(), "img@sha256:ccc", "sha256:ccc"); err != nil {
			t.Fatalf("scan failed instead of bypassing the cache: %v", err)
		}
	}
	if n := scans(t, counter); n != 2 {
		t.Fatalf("trivy ran %d times, want 2", n)
	}
}
