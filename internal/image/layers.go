package image

import (
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// LayerEntry maps one history entry to its DiffID and layer index.
type LayerEntry struct {
	Index   int
	DiffID  string
	Command string // created_by text from history
	IsEmpty bool   // empty layers (e.g. ENV, LABEL) have no DiffID
}

// LayerMap is a slice of LayerEntry ordered by layer index.
type LayerMap []LayerEntry

// BuildLayerMap walks the image history and assigns each non-empty history
// entry the next DiffID from rootfs.diff_ids (FR-03).
func BuildLayerMap(cf *v1.ConfigFile) (LayerMap, error) {
	diffIDs := cf.RootFS.DiffIDs
	history := cf.History

	var lm LayerMap
	diffIdx := 0

	for _, h := range history {
		entry := LayerEntry{
			Index:   diffIdx,
			Command: h.CreatedBy,
			IsEmpty: h.EmptyLayer,
		}
		if !h.EmptyLayer {
			if diffIdx >= len(diffIDs) {
				return nil, fmt.Errorf(
					"imgowner: history has more non-empty entries than diff_ids (got %d diff_ids)",
					len(diffIDs),
				)
			}
			entry.DiffID = diffIDs[diffIdx].String()
			diffIdx++
		}
		lm = append(lm, entry)
	}
	return lm, nil
}

// BaseLayerCount returns the number of layers that belong to the base image by
// verifying that the base image's diff_ids are an exact prefix of the final
// image's diff_ids (FR-04).
func BaseLayerCount(finalCF, baseCF *v1.ConfigFile) (int, error) {
	finalIDs := finalCF.RootFS.DiffIDs
	baseIDs := baseCF.RootFS.DiffIDs

	if len(baseIDs) > len(finalIDs) {
		return 0, fmt.Errorf(
			"imgowner: base image has more layers (%d) than final image (%d) — not a valid base",
			len(baseIDs), len(finalIDs),
		)
	}

	for i, bid := range baseIDs {
		if finalIDs[i] != bid {
			return 0, fmt.Errorf(
				"imgowner: diff_id mismatch at layer %d: base=%s final=%s — "+
					"image may be squashed or multi-platform",
				i, bid, finalIDs[i],
			)
		}
	}

	return len(baseIDs), nil
}

// FindByDiffID returns the LayerEntry for a given DiffID, or nil.
func (lm LayerMap) FindByDiffID(diffID string) *LayerEntry {
	for i := range lm {
		if lm[i].DiffID == diffID {
			return &lm[i]
		}
	}
	return nil
}
