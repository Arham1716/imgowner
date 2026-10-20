package image

import (
	"context"
	"fmt"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// BaseResolution describes where the base image ends in the final image's
// layer stack. Confident is false when the boundary could not be verified —
// in that case LayerCount is meaningless and callers must not attribute
// findings by layer position (FR-04, FR-06).
type BaseResolution struct {
	Ref        string // base reference actually used for the comparison
	Digest     string // resolved digest of that reference
	LayerCount int    // number of leading layers belonging to the base image
	Confident  bool   // true only when the diff_id prefix matched exactly
	Reason     string // why confidence is low; empty when Confident
}

// ResolveBase determines how many leading layers of finalCF belong to the base
// image named by baseRef.
//
// When digestOverride is non-empty the base image is pinned to that digest,
// which is the only reliable way to compare against an image built in the past:
// a floating tag such as python:3.12-slim moves over time, so resolving it today
// can yield a different image than the one the final image was actually built
// from. When the prefix check fails, the returned BaseResolution has
// Confident=false and an actionable Reason rather than a silent zero count.
func ResolveBase(
	ctx context.Context,
	finalCF *v1.ConfigFile,
	baseRef string,
	digestOverride string,
	platform string,
) *BaseResolution {
	res := &BaseResolution{Ref: baseRef}

	if baseRef == "" {
		res.Reason = "no FROM reference could be resolved from the Dockerfile"
		return res
	}

	ref := baseRef
	if digestOverride != "" {
		ref = pinToDigest(baseRef, digestOverride)
		res.Ref = ref
		res.Digest = digestOverride
	}

	baseCF, err := Config(ctx, ref, platform)
	if err != nil {
		res.Reason = fmt.Sprintf("could not fetch base image config for %s: %v", ref, err)
		return res
	}

	count, err := BaseLayerCount(finalCF, baseCF)
	if err != nil {
		res.Reason = baseMismatchReason(err, digestOverride)
		return res
	}

	res.LayerCount = count
	res.Confident = true
	return res
}

// baseMismatchReason turns a layer-prefix failure into guidance the user can act on.
func baseMismatchReason(err error, digestOverride string) string {
	if digestOverride != "" {
		// A pinned digest still failed to match, so this is not tag drift.
		return fmt.Sprintf(
			"base image layers do not prefix-match the scanned image even at the pinned digest (%v); "+
				"the image may be squashed, built by a non-standard builder, or built FROM a different base",
			err,
		)
	}
	return fmt.Sprintf(
		"base image layers do not prefix-match the scanned image (%v); "+
			"the FROM tag has most likely moved since this image was built — "+
			"re-run with --base-digest sha256:... to pin the base image used at build time",
		err,
	)
}

// pinToDigest rewrites a reference so it points at an explicit digest,
// dropping any digest the reference already carried.
func pinToDigest(ref, digest string) string {
	if idx := strings.Index(ref, "@"); idx >= 0 {
		ref = ref[:idx]
	}
	return ref + "@" + digest
}
