package scan

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const stamp = "vuln=2026-10-25T12:00:00Z"

// withIsolatedCacheDir points the cache at a fresh directory and returns it,
// so tests never touch (or are polluted by) the real user cache.
func withIsolatedCacheDir(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	old := userCacheDir
	userCacheDir = func() (string, error) { return base, nil }
	t.Cleanup(func() { userCacheDir = old })
	return filepath.Join(base, "imgowner", "scans")
}

// withClock fixes the cache's notion of now.
func withClock(t *testing.T, at time.Time) {
	t.Helper()
	old := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = old })
}

func TestCacheKey_DistinguishesDigestTrivyVersionAndDB(t *testing.T) {
	base := cacheKey("sha256:aaa", "0.76.0", stamp)
	for name, k := range map[string]string{
		"digest":        cacheKey("sha256:bbb", "0.76.0", stamp),
		"trivy version": cacheKey("sha256:aaa", "0.75.0", stamp),
		"vuln DB":       cacheKey("sha256:aaa", "0.76.0", "vuln=2026-10-26T12:00:00Z"),
	} {
		if k == base {
			t.Errorf("a different %s must produce a different cache key", name)
		}
	}
}

func TestCacheKey_IsFilesystemSafe(t *testing.T) {
	key := cacheKey("sha256:abc123", "0.76.0", "vuln=2026-10-25T12:00:00Z;java=x/y")
	if filepath.Base(key) != key {
		t.Errorf("cache key must not contain path separators, got %q", key)
	}
	for _, c := range []string{":", "/", "@", ";"} {
		if strings.Contains(key, c) {
			t.Errorf("cache key %q must not contain %q", key, c)
		}
	}
}

func TestReadCache_ColdMiss(t *testing.T) {
	withIsolatedCacheDir(t)
	data, err := ReadCache("sha256:nonexistent", "0.76.0", stamp)
	if err != nil || data != nil {
		t.Fatalf("cold cache: got %q, %v; want nil, nil", data, err)
	}
}

func TestWriteCache_ThenReadCache_RoundTrips(t *testing.T) {
	withIsolatedCacheDir(t)
	raw := []byte(`{"Results":[{"Target":"test"}]}`)
	if err := WriteCache("sha256:roundtrip", "0.76.0", stamp, raw); err != nil {
		t.Fatalf("WriteCache: %v", err)
	}
	got, err := ReadCache("sha256:roundtrip", "0.76.0", stamp)
	if err != nil {
		t.Fatalf("ReadCache: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("round-tripped cache content mismatch:\n got: %s\nwant: %s", got, raw)
	}
}

func TestReadCache_WrongTrivyVersionIsAMiss(t *testing.T) {
	withIsolatedCacheDir(t)
	if err := WriteCache("sha256:versioned", "0.75.0", stamp, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if got, _ := ReadCache("sha256:versioned", "0.76.0", stamp); got != nil {
		t.Error("an entry written under one trivy version must not satisfy a read for another")
	}
}

// The acceptance-test failure this fixes: a re-scan replayed the first result
// forever, so CVEs published after it never appeared. A DB update must miss.
func TestReadCache_AnUpdatedVulnerabilityDBIsAMiss(t *testing.T) {
	withIsolatedCacheDir(t)
	if err := WriteCache("sha256:img", "0.76.0", stamp, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if got, _ := ReadCache("sha256:img", "0.76.0", "vuln=2026-10-26T12:00:00Z"); got != nil {
		t.Error("a result from an older vulnerability DB was served after the DB updated")
	}
}

func TestCache_WithoutADBStampNothingIsReadOrWritten(t *testing.T) {
	dir := withIsolatedCacheDir(t)
	if err := WriteCache("sha256:img", "0.76.0", "", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("an entry was stored without a DB stamp: %v", entries)
	}
	if got, err := ReadCache("sha256:img", "0.76.0", ""); got != nil || err != nil {
		t.Errorf("ReadCache without a DB stamp = %q, %v; want nil, nil", got, err)
	}
}

func TestReadCache_EntriesExpire(t *testing.T) {
	withIsolatedCacheDir(t)
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	withClock(t, t0)
	if err := WriteCache("sha256:img", "0.76.0", stamp, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	withClock(t, t0.Add(maxCacheAge-time.Minute))
	if got, _ := ReadCache("sha256:img", "0.76.0", stamp); got == nil {
		t.Fatal("an entry younger than maxCacheAge was not served")
	}
	withClock(t, t0.Add(maxCacheAge+time.Minute))
	if got, _ := ReadCache("sha256:img", "0.76.0", stamp); got != nil {
		t.Error("an entry older than maxCacheAge was served")
	}
}

// An entry stamped far in the future would otherwise never expire.
func TestReadCache_AnEntryFromTheFutureIsAMiss(t *testing.T) {
	withIsolatedCacheDir(t)
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	withClock(t, t0.Add(48*time.Hour))
	if err := WriteCache("sha256:img", "0.76.0", stamp, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	withClock(t, t0)
	if got, _ := ReadCache("sha256:img", "0.76.0", stamp); got != nil {
		t.Error("an entry dated two days ahead was served")
	}
}

func TestReadCache_CorruptFileIsTreatedAsColdAndRemoved(t *testing.T) {
	dir := withIsolatedCacheDir(t)
	if _, err := cacheDir(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, cacheKey("sha256:corrupt", "0.76.0", stamp))
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := ReadCache("sha256:corrupt", "0.76.0", stamp)
	if err != nil || data != nil {
		t.Fatalf("corrupt cache: got %q, %v; want nil, nil", data, err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("corrupt cache file should be removed so it is not retried every run")
	}
}

func TestReadCache_OldSchemaIsTreatedAsCold(t *testing.T) {
	dir := withIsolatedCacheDir(t)
	if _, err := cacheDir(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, cacheKey("sha256:old", "0.76.0", stamp))
	old := `{"schema_version":"1","trivy_version":"0.76.0","raw":{"Results":[]}}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := ReadCache("sha256:old", "0.76.0", stamp); got != nil {
		t.Error("a schema-1 entry was served")
	}
}

func TestWriteCache_LeavesNoTemporaryFiles(t *testing.T) {
	dir := withIsolatedCacheDir(t)
	for i := 0; i < 3; i++ {
		if err := WriteCache("sha256:img", "0.76.0", stamp, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || strings.HasSuffix(entries[0].Name(), ".tmp") {
		t.Errorf("want exactly the one entry, got %v", entries)
	}
}

func TestCacheDir_IsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits; the Windows ACL is applied by securedir")
	}
	dir := withIsolatedCacheDir(t)
	if err := WriteCache("sha256:img", "0.76.0", stamp, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0o700 {
		t.Errorf("cache dir mode %o, want 0700", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	fi, _ := entries[0].Info()
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("cache entry mode %o, want 0600", fi.Mode().Perm())
	}
}

// A cache directory that is a symlink is refused, and the refusal is an
// error the runner turns into "scan afresh", never a trusted read.
func TestReadCache_RefusesASymlinkedCacheDir(t *testing.T) {
	base := t.TempDir()
	old := userCacheDir
	userCacheDir = func() (string, error) { return base, nil }
	t.Cleanup(func() { userCacheDir = old })
	elsewhere := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "imgowner"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(base, "imgowner", "scans")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	if _, err := ReadCache("sha256:img", "0.76.0", stamp); err == nil {
		t.Fatal("a symlinked cache directory was used")
	}
}
