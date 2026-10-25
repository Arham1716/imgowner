package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Arham1716/imgowner/internal/safeio"
	"github.com/Arham1716/imgowner/internal/securedir"
)

// cacheSchemaVersion is bumped whenever the envelope changes; older entries
// are then treated as cold.
const cacheSchemaVersion = "2"

// maxCacheAge bounds how long a stored scan is trusted even while Trivy's
// vulnerability DB reports no update (an offline run with --skip-db-update,
// say). A security scanner must not keep answering from a result that old.
const maxCacheAge = 24 * time.Hour

// clockSkew tolerates a scanned_at slightly in the future (clock adjustments)
// without accepting one far ahead, which would never expire.
const clockSkew = 5 * time.Minute

// userCacheDir and now are replaced in tests.
var (
	userCacheDir = os.UserCacheDir
	now          = time.Now
)

type cacheEnvelope struct {
	SchemaVersion string          `json:"schema_version"`
	TrivyVersion  string          `json:"trivy_version"`
	DBStamp       string          `json:"db_stamp"`
	ScannedAt     time.Time       `json:"scanned_at"`
	Raw           json.RawMessage `json:"raw"`
}

// cacheDir returns the per-user scan cache directory, creating it owner-only.
// It used to live in the shared temp directory, where another local user
// could create it first and plant a "no vulnerabilities" result for any
// image; securedir.Ensure refuses a directory someone else controls.
func cacheDir() (string, error) {
	base, err := userCacheDir()
	if err != nil {
		return "", fmt.Errorf("scan cache: locating the user cache directory: %w", err)
	}
	dir := filepath.Join(base, "imgowner", "scans")
	if err := securedir.Ensure(dir); err != nil {
		return "", fmt.Errorf("scan cache: %w", err)
	}
	return dir, nil
}

// cacheKey returns the filename for one scan: the image digest, the Trivy
// version (a schema change invalidates entries) and the vulnerability DB
// stamp (a DB update invalidates them, so newly published CVEs are found).
func cacheKey(digest, trivyVersion, dbStamp string) string {
	safe := strings.NewReplacer(":", "_", "/", "_", "@", "_").Replace(digest)
	db := sha256.Sum256([]byte(dbStamp))
	return fmt.Sprintf("%s__%s__%s.json", safe, strings.ReplaceAll(trivyVersion, ".", "_"), hex.EncodeToString(db[:8]))
}

// ReadCache returns the raw Trivy JSON for digest if an entry exists for this
// exact Trivy version and vulnerability DB and is younger than maxCacheAge.
// Returns nil, nil when the cache is cold, stale, or freshness can't be
// proven (an empty dbStamp). An error means the cache directory itself is
// unusable; the caller scans afresh.
func ReadCache(digest, trivyVersion, dbStamp string) ([]byte, error) {
	if dbStamp == "" {
		return nil, nil
	}
	dir, err := cacheDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, cacheKey(digest, trivyVersion, dbStamp))

	data, err := safeio.ReadFile(path, safeio.MaxTrivyReport)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scan cache: reading %s: %w", path, err)
	}

	var env cacheEnvelope
	if err := json.Unmarshal(data, &env); err != nil || env.SchemaVersion != cacheSchemaVersion {
		// Corrupt or from an older version: treat as cold and drop it.
		_ = os.Remove(path)
		return nil, nil
	}
	// The key already encodes these; checking them again costs nothing and
	// catches a file renamed into place.
	if env.TrivyVersion != trivyVersion || env.DBStamp != dbStamp {
		return nil, nil
	}
	age := now().Sub(env.ScannedAt)
	if age > maxCacheAge || age < -clockSkew {
		_ = os.Remove(path)
		return nil, nil
	}
	return env.Raw, nil
}

// WriteCache saves raw Trivy JSON for digest. It writes to a temporary file
// and renames it into place, so a crash or a concurrent run never leaves a
// half-written entry. Nothing is stored without a dbStamp, because such an
// entry could never be proven fresh.
func WriteCache(digest, trivyVersion, dbStamp string, raw []byte) error {
	if dbStamp == "" {
		return nil
	}
	dir, err := cacheDir()
	if err != nil {
		return err
	}
	data, err := json.Marshal(cacheEnvelope{
		SchemaVersion: cacheSchemaVersion,
		TrivyVersion:  trivyVersion,
		DBStamp:       dbStamp,
		ScannedAt:     now().UTC(),
		Raw:           json.RawMessage(raw),
	})
	if err != nil {
		return fmt.Errorf("scan cache: encoding entry: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".scan-*.tmp") // created 0600
	if err != nil {
		return fmt.Errorf("scan cache: %w", err)
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("scan cache: writing entry: %w", errors.Join(werr, cerr))
	}
	path := filepath.Join(dir, cacheKey(digest, trivyVersion, dbStamp))
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("scan cache: %w", err)
	}
	return nil
}
