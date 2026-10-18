package pins

import (
	"fmt"
	"os"
)

// Edit represents a single byte-level version replacement in a Dockerfile.
type Edit struct {
	ByteOffset int    // byte offset of the old version string
	OldVersion string // version string being replaced
	NewVersion string // replacement version string
}

// PlanEdits builds the list of byte-level edits needed to update the given
// pins to their Available versions (Story 3.1, FR-17).
// Only pins with Status == StatusUpdateAvailable or StatusFixesCVEs are included.
func PlanEdits(pinList []Pin) []Edit {
	var edits []Edit
	for _, p := range pinList {
		if p.Status != StatusUpdateAvailable && p.Status != StatusFixesCVEs {
			continue
		}
		if p.Available == "" || p.ByteOffset < 0 {
			continue
		}
		edits = append(edits, Edit{
			ByteOffset: p.ByteOffset,
			OldVersion: p.Version,
			NewVersion: p.Available,
		})
	}
	return edits
}

// ApplyEdits applies a set of byte-level edits to content and returns the
// updated Dockerfile bytes (FR-17). Edits must not overlap; they are applied
// in reverse byte-offset order so earlier offsets remain valid.
func ApplyEdits(content []byte, edits []Edit) ([]byte, error) {
	if len(edits) == 0 {
		return content, nil
	}

	// Sort edits by byte offset descending so we can apply right-to-left
	// without invalidating earlier offsets.
	sorted := make([]Edit, len(edits))
	copy(sorted, edits)
	sortEditsDesc(sorted)

	result := make([]byte, len(content))
	copy(result, content)

	for _, e := range sorted {
		start := e.ByteOffset
		end := start + len(e.OldVersion)
		if start < 0 || end > len(result) {
			return nil, fmt.Errorf("edit out of bounds: offset %d len %d in %d-byte file",
				start, len(e.OldVersion), len(result))
		}
		// Verify the expected old version is at the recorded offset.
		actual := string(result[start:end])
		if actual != e.OldVersion {
			return nil, fmt.Errorf("edit mismatch at offset %d: expected %q found %q",
				start, e.OldVersion, actual)
		}
		// Replace in-place (may change file length).
		result = append(result[:start], append([]byte(e.NewVersion), result[end:]...)...)
	}
	return result, nil
}

// WriteDockerfile writes updated content to path, preserving the original
// file's permissions.
func WriteDockerfile(path string, content []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	return os.WriteFile(path, content, info.Mode())
}

// sortEditsDesc sorts edits by ByteOffset descending (in-place insertion sort;
// edit lists are short — at most a few dozen entries).
func sortEditsDesc(edits []Edit) {
	for i := 1; i < len(edits); i++ {
		for j := i; j > 0 && edits[j].ByteOffset > edits[j-1].ByteOffset; j-- {
			edits[j], edits[j-1] = edits[j-1], edits[j]
		}
	}
}
