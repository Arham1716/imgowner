package history

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/pins"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "history"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func sampleInput() Input {
	return Input{
		Command:    "attribute",
		Image:      "registry.local/app:1",
		Digest:     "sha256:abc",
		BaseRef:    "debian:12-slim",
		Dockerfile: "Dockerfile",
		Findings: []attribution.Finding{
			{CVE: "CVE-1", Severity: "HIGH", Package: "curl", Owner: attribution.OwnerAddedOS,
				Instruction: &attribution.DockerfileRef{Line: 7, Text: "RUN apt-get install curl"}},
			{CVE: "CVE-2", Severity: "LOW", Package: "libc6", Owner: attribution.OwnerBase},
			{CVE: "CVE-3", Severity: "HIGH", Package: "zlib", Owner: attribution.OwnerBase},
		},
	}
}

// FR-31: a record written after a scan reads back with the same content, and
// its summary carries the per-owner counts the dashboard charts.
func TestAppendThenGet_RoundTrips(t *testing.T) {
	s := newStore(t)
	id, err := s.Append(NewRecord(sampleInput()))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	rec, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Summary.ID != id || rec.Summary.Image != "registry.local/app:1" || rec.Summary.Digest != "sha256:abc" {
		t.Errorf("summary mismatch: %+v", rec.Summary)
	}
	if rec.Summary.Counts["base"] != 2 || rec.Summary.Counts["added-os"] != 1 {
		t.Errorf("counts = %v, want base=2 added-os=1", rec.Summary.Counts)
	}
	if rec.Summary.Severities["HIGH"] != 2 || rec.Summary.Severities["LOW"] != 1 {
		t.Errorf("severities = %v, want HIGH=2 LOW=1", rec.Summary.Severities)
	}
	if len(rec.Findings) != 3 || rec.Findings[0].Instruction == nil || rec.Findings[0].Instruction.Line != 7 {
		t.Errorf("findings did not round-trip: %+v", rec.Findings)
	}
}

func TestNewRecord_NoFindingsEncodesEmptyArrayNotNull(t *testing.T) {
	s := newStore(t)
	id, err := s.Append(NewRecord(Input{Command: "attribute", Image: "x"}))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"findings":[]`) {
		t.Errorf("a scan with no findings must store [], not null; got %s", data)
	}
}

func TestNewRecord_CountsPinStatuses(t *testing.T) {
	rec := NewRecord(Input{Command: "pins-check", Pins: []pins.Pin{
		{Package: "curl", Status: pins.StatusCurrent},
		{Package: "wget", Status: pins.StatusUpdateAvailable},
		{Package: "git", Status: pins.StatusUpdateAvailable},
	}})
	if rec.Summary.PinStatuses["update-available"] != 2 || rec.Summary.PinStatuses["current"] != 1 {
		t.Errorf("pin statuses = %v", rec.Summary.PinStatuses)
	}
}

// NFR-12: the directory and every record are readable by the owner only.
func TestOpenAndAppend_OwnerOnlyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits don't apply; Windows relies on the %LOCALAPPDATA% ACL")
	}
	s := newStore(t)
	id, err := s.Append(NewRecord(sampleInput()))
	if err != nil {
		t.Fatal(err)
	}
	di, _ := os.Stat(s.Dir())
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %o, want 700", di.Mode().Perm())
	}
	fi, _ := os.Stat(s.path(id))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("record mode = %o, want 600", fi.Mode().Perm())
	}
}

func TestOpen_TightensAnExistingOpenDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits don't apply on Windows")
	}
	dir := filepath.Join(t.TempDir(), "history")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err != nil {
		t.Fatalf("Open: %v", err)
	}
	fi, _ := os.Stat(dir)
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("an existing group/world-accessible dir must be restricted, mode = %o", fi.Mode().Perm())
	}
}

// A reader must never observe a half-written record, and a successful append
// must leave no temp file behind.
func TestAppend_LeavesNoTempFiles(t *testing.T) {
	s := newStore(t)
	if _, err := s.Append(NewRecord(sampleInput())); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(s.Dir())
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly one record file, got %d", len(entries))
	}
}

// Several imgowner processes (a CI matrix on one machine) can write at once.
func TestAppend_ConcurrentWritersGetUniqueIDs(t *testing.T) {
	s := newStore(t)
	const n = 40
	ids := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := s.Append(NewRecord(sampleInput()))
			if err != nil {
				t.Errorf("Append: %v", err)
			}
			ids[i] = id
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id] = true
	}
	sums, skipped, err := s.List()
	if err != nil || skipped != 0 || len(sums) != n {
		t.Errorf("List = %d summaries, %d skipped, err %v; want %d, 0, nil", len(sums), skipped, err, n)
	}
}

func TestList_NewestFirstAndSummariesOnly(t *testing.T) {
	s := newStore(t)
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		i := i
		s.now = func() time.Time { return base.Add(time.Duration(i) * time.Hour) }
		in := sampleInput()
		in.Image = "img" + string(rune('a'+i))
		if _, err := s.Append(NewRecord(in)); err != nil {
			t.Fatal(err)
		}
	}
	sums, skipped, err := s.List()
	if err != nil || skipped != 0 {
		t.Fatalf("List: skipped=%d err=%v", skipped, err)
	}
	if len(sums) != 3 || sums[0].Image != "imgc" || sums[2].Image != "imga" {
		t.Errorf("expected newest first (imgc, imgb, imga), got %+v", sums)
	}
}

// One bad file in the directory must not take the whole listing down.
func TestList_SkipsCorruptAndMismatchedFiles(t *testing.T) {
	s := newStore(t)
	good, err := s.Append(NewRecord(sampleInput()))
	if err != nil {
		t.Fatal(err)
	}
	write := func(id, content string) {
		if err := os.WriteFile(s.path(id), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("20260101T000000.000000000Z-deadbeef", "{not json")
	write("20260102T000000.000000000Z-deadbeef", `{"findings":[]}`) // no leading summary
	write("20260103T000000.000000000Z-deadbeef",
		`{"summary":{"id":"20260101T000000.000000000Z-00000000"}}`) // id doesn't match file
	// Unrelated files are ignored without being counted as bad records.
	if err := os.WriteFile(filepath.Join(s.Dir(), "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	sums, skipped, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(sums) != 1 || sums[0].ID != good {
		t.Errorf("only the good record should be listed, got %+v", sums)
	}
	if skipped != 3 {
		t.Errorf("skipped = %d, want 3 (corrupt, no-summary, id-mismatch)", skipped)
	}
}

func TestList_SkipsASymlinkNamedLikeARecord(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs elevated rights on Windows")
	}
	s := newStore(t)
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"summary":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	id := "20260101T000000.000000000Z-deadbeef"
	if err := os.Symlink(target, s.path(id)); err != nil {
		t.Fatal(err)
	}
	sums, skipped, _ := s.List()
	if len(sums) != 0 || skipped != 1 {
		t.Errorf("a symlink must be skipped, got %d summaries / %d skipped", len(sums), skipped)
	}
	if _, err := s.Get(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get on a symlink = %v, want ErrNotFound", err)
	}
}

// The dashboard passes ids straight from request paths into Get.
func TestGet_RejectsPathTraversalAndMalformedIDs(t *testing.T) {
	s := newStore(t)
	for _, id := range []string{
		"", "../../etc/passwd", "..", "a/b", `..\..\x`,
		"20260101T000000.000000000Z-deadbeef/../x",
		"20260101T000000.000000000Z-DEADBEEF", // wrong case
		"20260101T000000.000000000Z-deadbee",  // short
		"20260101T000000.000000000Z-deadbeef.json",
	} {
		if _, err := s.Get(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Get(%q) = %v, want ErrInvalidID", id, err)
		}
	}
	if _, err := s.Get("20260101T000000.000000000Z-deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a well-formed but absent id should be ErrNotFound")
	}
}

// FR-32: records older than the retention window are deleted when a new one
// is written; younger ones stay.
func TestPrune_DeletesOnlyRecordsOlderThanRetention(t *testing.T) {
	s := newStore(t)
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	ages := map[string]int{"old": 100, "mid": 60, "new": 1}
	ids := map[string]string{}
	for name, days := range ages {
		days := days
		s.now = func() time.Time { return now.AddDate(0, 0, -days) }
		id, err := s.Append(NewRecord(sampleInput()))
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = id
	}
	s.now = func() time.Time { return now }
	removed, err := s.Prune(90)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if _, err := s.Get(ids["old"]); !errors.Is(err, ErrNotFound) {
		t.Errorf("the 100-day-old record should be gone, Get = %v", err)
	}
	for _, name := range []string{"mid", "new"} {
		if _, err := s.Get(ids[name]); err != nil {
			t.Errorf("the %s record must survive: %v", name, err)
		}
	}
}

func TestPrune_RefusesRetentionBelowOneDay(t *testing.T) {
	s := newStore(t)
	if _, err := s.Append(NewRecord(sampleInput())); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prune(0); err == nil {
		t.Fatal("Prune(0) must error rather than delete everything")
	}
	if sums, _, _ := s.List(); len(sums) != 1 {
		t.Errorf("the record must still be there, got %d", len(sums))
	}
}

// Prune only ever touches files shaped like the store's own records.
func TestPrune_LeavesForeignFilesAlone(t *testing.T) {
	s := newStore(t)
	foreign := filepath.Join(s.Dir(), "important-notes.json")
	if err := os.WriteFile(foreign, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(-1, 0, 0)
	_ = os.Chtimes(foreign, old, old)
	if _, err := s.Prune(1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("a file that isn't a record must never be deleted: %v", err)
	}
}

func TestAppend_RejectsAnOversizedRecord(t *testing.T) {
	s := newStore(t)
	in := sampleInput()
	in.Findings[0].Package = strings.Repeat("x", MaxRecordBytes+1)
	if _, err := s.Append(NewRecord(in)); err == nil {
		t.Fatal("a record over the size limit must be rejected")
	}
	if entries, _ := os.ReadDir(s.Dir()); len(entries) != 0 {
		t.Errorf("a rejected record must leave nothing behind, found %d files", len(entries))
	}
}

func TestDecodeRecord_RejectsUnknownSchemaVersion(t *testing.T) {
	if _, err := DecodeRecord([]byte(`{"summary":{},"schema_version":99,"findings":[]}`)); err == nil {
		t.Error("an unknown schema version must be rejected, not half-read")
	}
}

func TestDefaultDir_IsPerUserNotWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("LOCALAPPDATA", `C:\Users\x\AppData\Local`)
	} else {
		t.Setenv("XDG_STATE_HOME", "/home/x/.local/state")
		t.Setenv("HOME", "/home/x")
	}
	d, err := DefaultDir()
	if err != nil {
		t.Fatalf("DefaultDir: %v", err)
	}
	if !filepath.IsAbs(d) || !strings.HasSuffix(filepath.ToSlash(d), "imgowner/history") {
		t.Errorf("DefaultDir = %q, want an absolute .../imgowner/history", d)
	}
}

// Records are immutable, so listing reads a file once. But the listing must
// still follow the directory: a record another process adds shows up, and one
// that is deleted (retention) disappears.
func TestList_CacheFollowsTheDirectory(t *testing.T) {
	s := newStore(t)
	a, err := s.Append(NewRecord(sampleInput()))
	if err != nil {
		t.Fatal(err)
	}
	if sums, _, _ := s.List(); len(sums) != 1 || sums[0].ID != a {
		t.Fatalf("first listing = %+v", sums)
	}

	// Another process (a second Store over the same directory) writes a record.
	other, err := Open(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := other.Append(NewRecord(sampleInput()))
	if err != nil {
		t.Fatal(err)
	}
	if sums, _, _ := s.List(); len(sums) != 2 {
		t.Fatalf("a record written by another process must appear, got %d", len(sums))
	}

	// Retention deletes the first one.
	if err := os.Remove(s.path(a)); err != nil {
		t.Fatal(err)
	}
	sums, _, _ := s.List()
	if len(sums) != 1 || sums[0].ID != b {
		t.Fatalf("a deleted record must drop out of the listing, got %+v", sums)
	}
}

// A file that could not be read is retried on the next listing, not cached as bad.
func TestList_UnreadableFileIsRetried(t *testing.T) {
	s := newStore(t)
	id := "20260101T000000.000000000Z-deadbeef"
	if err := os.WriteFile(s.path(id), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, skipped, _ := s.List(); skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	good := `{"summary":{"id":"` + id + `","counts":{}}}`
	if err := os.WriteFile(s.path(id), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if sums, skipped, _ := s.List(); len(sums) != 1 || skipped != 0 {
		t.Errorf("after the file is fixed: %d summaries, %d skipped; want 1, 0", len(sums), skipped)
	}
}
