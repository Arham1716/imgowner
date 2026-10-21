package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// Isolate cache tests from the real $TMPDIR/imgowner cache so parallel test
// runs, or a prior crashed run, cannot leak a stale entry into these tests.
func withIsolatedCacheDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir) // os.TempDir() reads TMPDIR on Unix
	t.Setenv("TMP", dir)    // ... and TMP, then TEMP, on Windows
	t.Setenv("TEMP", dir)
}

func TestCacheKey_DistinctForDifferentDigests(t *testing.T) {
	k1 := cacheKey("sha256:aaa", "0.76.0")
	k2 := cacheKey("sha256:bbb", "0.76.0")
	if k1 == k2 {
		t.Error("different digests must produce different cache keys")
	}
}

// A Trivy upgrade must invalidate the cache rather than serve stale findings
// under a new schema (FR: cache keyed by digest+trivyVersion, DQ-1).
func TestCacheKey_DistinctForDifferentTrivyVersions(t *testing.T) {
	k1 := cacheKey("sha256:aaa", "0.75.0")
	k2 := cacheKey("sha256:aaa", "0.76.0")
	if k1 == k2 {
		t.Error("different trivy versions must produce different cache keys for the same digest")
	}
}

func TestCacheKey_IsFilesystemSafe(t *testing.T) {
	key := cacheKey("sha256:abc123", "0.76.0")
	if filepath.Base(key) != key {
		t.Errorf("cache key must not contain path separators, got %q", key)
	}
	for _, c := range []string{":", "/", "@"} {
		if containsRune(key, c) {
			t.Errorf("cache key %q must not contain %q", key, c)
		}
	}
}

func containsRune(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestReadCache_ColdMiss(t *testing.T) {
	withIsolatedCacheDir(t)
	data, err := ReadCache("sha256:nonexistent", "0.76.0")
	if err != nil {
		t.Fatalf("cold cache must not error, got: %v", err)
	}
	if data != nil {
		t.Error("cold cache must return nil data")
	}
}

func TestWriteCache_ThenReadCache_RoundTrips(t *testing.T) {
	withIsolatedCacheDir(t)
	raw := []byte(`{"Results":[{"Target":"test"}]}`)

	if err := WriteCache("sha256:roundtrip", "0.76.0", raw); err != nil {
		t.Fatalf("WriteCache: %v", err)
	}
	got, err := ReadCache("sha256:roundtrip", "0.76.0")
	if err != nil {
		t.Fatalf("ReadCache: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("round-tripped cache content mismatch:\n got: %s\nwant: %s", got, raw)
	}
}

// Caching under a different Trivy version must not satisfy a lookup for the
// version actually installed — the whole point of keying by version.
func TestReadCache_WrongTrivyVersionIsAMiss(t *testing.T) {
	withIsolatedCacheDir(t)
	if err := WriteCache("sha256:versioned", "0.75.0", []byte(`{}`)); err != nil {
		t.Fatalf("WriteCache: %v", err)
	}
	got, err := ReadCache("sha256:versioned", "0.76.0")
	if err != nil {
		t.Fatalf("ReadCache: %v", err)
	}
	if got != nil {
		t.Error("cache entry written under one trivy version must not satisfy a read for another")
	}
}

// A corrupted cache file must degrade to a cold miss, not propagate a parse
// error up through the scan path and fail the whole command.
func TestReadCache_CorruptFileIsTreatedAsCold(t *testing.T) {
	withIsolatedCacheDir(t)
	dir, err := cacheDir()
	if err != nil {
		t.Fatalf("cacheDir: %v", err)
	}
	path := filepath.Join(dir, cacheKey("sha256:corrupt", "0.76.0"))
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("writing corrupt cache file: %v", err)
	}

	data, err := ReadCache("sha256:corrupt", "0.76.0")
	if err != nil {
		t.Fatalf("corrupt cache must not error, got: %v", err)
	}
	if data != nil {
		t.Error("corrupt cache must return nil data")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("corrupt cache file should be removed so it is not retried every run")
	}
}

// An old on-disk schema version must not be served to code expecting the
// current one (F2: schema-mismatch handling).
func TestReadCache_SchemaVersionMismatchIsTreatedAsCold(t *testing.T) {
	withIsolatedCacheDir(t)
	dir, err := cacheDir()
	if err != nil {
		t.Fatalf("cacheDir: %v", err)
	}
	path := filepath.Join(dir, cacheKey("sha256:oldschema", "0.76.0"))
	stale := `{"schema_version":"0","trivy_version":"0.76.0","raw":{}}`
	if err := os.WriteFile(path, []byte(stale), 0o600); err != nil {
		t.Fatalf("writing stale-schema cache file: %v", err)
	}

	data, err := ReadCache("sha256:oldschema", "0.76.0")
	if err != nil {
		t.Fatalf("schema mismatch must not error, got: %v", err)
	}
	if data != nil {
		t.Error("schema-mismatched cache must be treated as cold")
	}
}
