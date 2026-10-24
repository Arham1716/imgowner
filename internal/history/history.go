// Package history is the local scan history store (FR-31, FR-32): one JSON
// file per scan under the user's own state directory, read back by the local
// dashboard. It never leaves the machine and never holds credentials
// (NFR-12).
//
// Layout: <dir>/<id>.json, where <id> is "<UTC timestamp>-<8 hex random>".
// Each file is a single JSON document whose first key is "summary", so the
// dashboard can list thousands of scans by reading only the first few
// kilobytes of each instead of every finding of every scan (NFR-17).
package history

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/baserec"
	"github.com/Arham1716/imgowner/internal/pins"
	"github.com/Arham1716/imgowner/internal/safeio"
)

// SchemaVersion is bumped when Record changes incompatibly.
const SchemaVersion = 1

// MaxRecordBytes bounds both writing and reading a record (NFR-13). A real
// scan is well under 2 MiB; anything past this is corrupt or hostile.
const MaxRecordBytes = 8 << 20

// maxSummaryBytes bounds how much of a file is read to get its summary.
const maxSummaryBytes = 64 << 10

const idTimeLayout = "20060102T150405.000000000Z"

// idPattern is the only shape of record id the store ever creates or accepts.
// Get takes ids from HTTP requests, so this is also what keeps "../../etc/x"
// from ever reaching the filesystem.
var idPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[0-9a-f]{8}$`)

// ErrNotFound is returned by Get for an id with no record.
var ErrNotFound = errors.New("history: record not found")

// ErrInvalidID is returned for an id that is not a well-formed record id.
var ErrInvalidID = errors.New("history: invalid record id")

// Summary is the small, always-read header of a record.
type Summary struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Command    string    `json:"command"` // attribute | ci | pins-check
	Image      string    `json:"image"`
	Digest     string    `json:"digest,omitempty"`
	BaseRef    string    `json:"base_ref,omitempty"`
	Dockerfile string    `json:"dockerfile,omitempty"`
	// Counts is findings per owner (base, added-os, app, unattributed).
	Counts map[string]int `json:"counts"`
	// Severities is findings per severity.
	Severities map[string]int `json:"severities,omitempty"`
	// PinStatuses is pins per status, for pins-check records.
	PinStatuses map[string]int `json:"pin_statuses,omitempty"`
}

// Record is one stored scan. Summary must stay the first field: List reads
// only the leading summary object.
type Record struct {
	Summary       Summary               `json:"summary"`
	SchemaVersion int                   `json:"schema_version"`
	Findings      []attribution.Finding `json:"findings"`
	Pins          []pins.Pin            `json:"pins,omitempty"`
	Candidates    []baserec.Candidate   `json:"base_candidates,omitempty"`
}

// Input is what a command hands over after a successful run.
type Input struct {
	Command    string
	Image      string
	Digest     string
	BaseRef    string
	Dockerfile string
	Findings   []attribution.Finding
	Pins       []pins.Pin
	Candidates []baserec.Candidate
}

// NewRecord builds a record with its summary counts derived from the input.
// ID and Timestamp are assigned by Store.Append.
func NewRecord(in Input) Record {
	s := Summary{
		Command:    in.Command,
		Image:      in.Image,
		Digest:     in.Digest,
		BaseRef:    in.BaseRef,
		Dockerfile: in.Dockerfile,
		Counts:     map[string]int{},
	}
	for _, f := range in.Findings {
		s.Counts[string(f.Owner)]++
		if f.Severity != "" {
			if s.Severities == nil {
				s.Severities = map[string]int{}
			}
			s.Severities[f.Severity]++
		}
	}
	for _, p := range in.Pins {
		if s.PinStatuses == nil {
			s.PinStatuses = map[string]int{}
		}
		s.PinStatuses[string(p.Status)]++
	}
	findings := in.Findings
	if findings == nil {
		findings = []attribution.Finding{} // "[]", not "null", for every reader
	}
	return Record{
		Summary:       s,
		SchemaVersion: SchemaVersion,
		Findings:      findings,
		Pins:          in.Pins,
		Candidates:    in.Candidates,
	}
}

// DefaultDir is the per-user location of the store: the platform's own
// convention for application state, not the working directory (so a scan run
// from a shared checkout never writes into it).
func DefaultDir() (string, error) {
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("LOCALAPPDATA")
		if base == "" {
			return "", errors.New("history: %LOCALAPPDATA% is not set")
		}
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("history: locating home directory: %w", err)
		}
		base = filepath.Join(home, "Library", "Application Support")
	default:
		base = os.Getenv("XDG_STATE_HOME")
		if base == "" || !filepath.IsAbs(base) {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("history: locating home directory: %w", err)
			}
			base = filepath.Join(home, ".local", "state")
		}
	}
	return filepath.Join(base, "imgowner", "history"), nil
}

// Store reads and writes records under one directory.
type Store struct {
	dir string
	now func() time.Time
}

// Open prepares dir (creating it owner-only) and returns a Store. An empty
// dir means DefaultDir.
func Open(dir string) (*Store, error) {
	if dir == "" {
		d, err := DefaultDir()
		if err != nil {
			return nil, err
		}
		dir = d
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("history: creating %s: %w", dir, err)
	}
	// MkdirAll leaves an existing directory's mode alone; tighten one that a
	// user (or an older version) made group/world accessible. Windows has no
	// such mode bits -- there %LOCALAPPDATA% already carries a per-user ACL.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dir)
		if err != nil {
			return nil, fmt.Errorf("history: %w", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			if err := os.Chmod(dir, 0o700); err != nil {
				return nil, fmt.Errorf("history: %s is accessible to other users and could not be restricted: %w", dir, err)
			}
		}
	}
	return &Store{dir: dir, now: time.Now}, nil
}

// WithClock returns a Store over the same directory that stamps records (and
// judges their age) with now instead of the wall clock. It exists so callers'
// tests can control time without sleeping.
func (s *Store) WithClock(now func() time.Time) *Store {
	return &Store{dir: s.dir, now: now}
}

// Dir returns the directory the store uses.
func (s *Store) Dir() string { return s.dir }

// Append assigns rec an id and timestamp and writes it atomically: the data
// goes to a temp file in the same directory, which is then renamed into
// place, so a reader (the dashboard) never sees a half-written record and a
// crash leaves at most a stale temp file.
func (s *Store) Append(rec Record) (string, error) {
	now := s.now().UTC()
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", fmt.Errorf("history: generating id: %w", err)
	}
	id := now.Format(idTimeLayout) + "-" + hex.EncodeToString(suffix)
	rec.Summary.ID = id
	rec.Summary.Timestamp = now
	rec.SchemaVersion = SchemaVersion

	data, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("history: encoding record: %w", err)
	}
	if len(data) > MaxRecordBytes {
		return "", &safeio.TooLargeError{What: "history record", Limit: MaxRecordBytes}
	}

	tmp, err := os.CreateTemp(s.dir, ".tmp-*") // 0600, O_EXCL
	if err != nil {
		return "", fmt.Errorf("history: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("history: writing record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("history: writing record: %w", err)
	}
	if err := os.Rename(tmpName, s.path(id)); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("history: committing record: %w", err)
	}
	return id, nil
}

func (s *Store) path(id string) string { return filepath.Join(s.dir, id+".json") }

// Prune deletes records older than retentionDays (FR-32). Age comes from the
// timestamp in the file name, so no record has to be opened. Only files that
// match the store's own naming are ever removed.
func (s *Store) Prune(retentionDays int) (int, error) {
	if retentionDays < 1 {
		return 0, fmt.Errorf("history: retention must be at least 1 day (got %d)", retentionDays)
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, fmt.Errorf("history: %w", err)
	}
	cutoff := s.now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	removed := 0
	var firstErr error
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".tmp-") {
			// A temp file this old belongs to a process that died mid-write.
			if info, err := e.Info(); err == nil && s.now().Sub(info.ModTime()) > time.Hour {
				_ = os.Remove(filepath.Join(s.dir, name))
			}
			continue
		}
		id, ok := recordID(name)
		if !ok || !e.Type().IsRegular() {
			continue
		}
		ts, err := time.Parse(idTimeLayout, strings.SplitN(id, "-", 2)[0])
		if err != nil || !ts.Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("history: pruning %s: %w", name, err)
			}
			continue
		}
		removed++
	}
	return removed, firstErr
}

// recordID returns the id a file name encodes, if it is a store-shaped name.
func recordID(name string) (string, bool) {
	id, ok := strings.CutSuffix(name, ".json")
	if !ok || !idPattern.MatchString(id) {
		return "", false
	}
	return id, true
}

// List returns the summary of every readable record, newest first. Files
// that are corrupt, oversized, not regular files (symlinks included) or not
// named like a record are skipped and counted, never fatal: one bad file must
// not take the whole dashboard down.
func (s *Store) List() (summaries []Summary, skipped int, err error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, 0, fmt.Errorf("history: %w", err)
	}
	for _, e := range entries {
		id, ok := recordID(e.Name())
		if !ok {
			continue
		}
		if !e.Type().IsRegular() {
			skipped++
			continue
		}
		sum, err := s.readSummary(id)
		if err != nil {
			skipped++
			continue
		}
		summaries = append(summaries, sum)
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].ID > summaries[j].ID })
	return summaries, skipped, nil
}

func (s *Store) readSummary(id string) (Summary, error) {
	f, err := os.Open(s.path(id)) // #nosec G304 -- id matched idPattern; path stays inside the store dir
	if err != nil {
		return Summary{}, err
	}
	defer func() { _ = f.Close() }()
	return decodeSummary(io.LimitReader(f, maxSummaryBytes), id)
}

// decodeSummary reads just the leading "summary" object of a record.
func decodeSummary(r io.Reader, wantID string) (Summary, error) {
	dec := json.NewDecoder(bufio.NewReaderSize(r, 8<<10))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return Summary{}, errors.New("history: record is not a JSON object")
	}
	key, err := dec.Token()
	if err != nil || key != "summary" {
		return Summary{}, errors.New("history: record does not start with its summary")
	}
	var sum Summary
	if err := dec.Decode(&sum); err != nil {
		return Summary{}, fmt.Errorf("history: decoding summary: %w", err)
	}
	if wantID != "" && sum.ID != wantID {
		return Summary{}, errors.New("history: summary id does not match its file name")
	}
	return sum, nil
}

// Get returns the full record for id.
func (s *Store) Get(id string) (*Record, error) {
	if !idPattern.MatchString(id) {
		return nil, ErrInvalidID
	}
	path := s.path(id)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("history: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNotFound // a symlink or device is not a record
	}
	data, err := safeio.ReadFile(path, MaxRecordBytes)
	if err != nil {
		return nil, fmt.Errorf("history: reading %s: %w", id, err)
	}
	rec, err := DecodeRecord(data)
	if err != nil {
		return nil, err
	}
	if rec.Summary.ID != id {
		return nil, errors.New("history: record id does not match its file name")
	}
	return rec, nil
}

// DecodeRecord parses a stored record. It is the one place untrusted record
// bytes are turned into values, and is fuzzed (FR-46).
func DecodeRecord(data []byte) (*Record, error) {
	if len(data) > MaxRecordBytes {
		return nil, &safeio.TooLargeError{What: "history record", Limit: MaxRecordBytes}
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("history: decoding record: %w", err)
	}
	if rec.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("history: unsupported record schema version %d", rec.SchemaVersion)
	}
	return &rec, nil
}
