package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Arham1716/imgowner/internal/safeio"
)

const cacheSchemaVersion = "1"

type cacheEnvelope struct {
	SchemaVersion string          `json:"schema_version"`
	TrivyVersion  string          `json:"trivy_version"`
	Raw           json.RawMessage `json:"raw"`
}

// cacheDir returns the directory used for scan result caching.
func cacheDir() (string, error) {
	tmp := os.TempDir()
	dir := filepath.Join(tmp, "imgowner")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("imgowner: creating cache dir: %w", err)
	}
	return dir, nil
}

// cacheKey returns the filename for a given image digest + trivy version.
// Including trivyVersion in the key handles the schema-mismatch case (F2).
func cacheKey(digest, trivyVersion string) string {
	safe := strings.NewReplacer(":", "_", "/", "_", "@", "_").Replace(digest)
	return fmt.Sprintf("%s__%s.json", safe, strings.ReplaceAll(trivyVersion, ".", "_"))
}

// ReadCache returns the raw Trivy JSON for digest if a valid cache entry exists.
// Returns nil, nil when the cache is cold or stale.
func ReadCache(digest, trivyVersion string) ([]byte, error) {
	dir, err := cacheDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, cacheKey(digest, trivyVersion))

	data, err := safeio.ReadFile(path, safeio.MaxTrivyReport)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("imgowner: reading cache: %w", err)
	}

	var env cacheEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		// Corrupt cache — treat as cold.
		_ = os.Remove(path)
		return nil, nil
	}
	if env.SchemaVersion != cacheSchemaVersion {
		_ = os.Remove(path)
		return nil, nil
	}

	return env.Raw, nil
}

// WriteCache saves raw Trivy JSON to the cache keyed by digest + trivyVersion.
func WriteCache(digest, trivyVersion string, raw []byte) error {
	dir, err := cacheDir()
	if err != nil {
		return err
	}

	env := cacheEnvelope{
		SchemaVersion: cacheSchemaVersion,
		TrivyVersion:  trivyVersion,
		Raw:           json.RawMessage(raw),
	}
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("imgowner: marshalling cache: %w", err)
	}

	path := filepath.Join(dir, cacheKey(digest, trivyVersion))
	return os.WriteFile(path, data, 0o600)
}
