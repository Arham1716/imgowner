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

// ResolveBaseImage is ResolveBase, additionally returning the opened
// ImageInfo for the base image so the caller can scan that exact image —
// needed for base-image recommendation (FR-10): comparing candidates against
// the final image's own scan would count every app- and added-os-layer CVE
// as "removed" by switching base, since a candidate trivially lacks CVEs
// that were never in the base to begin with.
//
// The returned ImageInfo is nil whenever there is nothing to scan (no FROM,
// FROM scratch, or resolution failed — see BaseResolution.Reason); otherwise
// the caller must Close it. ImageInfo.Close is nil-safe, so
// `defer func() { _ = info.Close() }()` is always correct.
//
// When digestOverride is non-empty the base image is pinned to that digest,
// which is the only reliable way to compare against an image built in the past:
// a floating tag such as python:3.12-slim moves over time, so resolving it today
// can yield a different image than the one the final image was actually built
// from. When the prefix check fails, the returned BaseResolution has
// Confident=false and an actionable Reason rather than a silent zero count.
func ResolveBaseImage(
	ctx context.Context,
	finalCF *v1.ConfigFile,
	baseRef string,
	digestOverride string,
	platform string,
) (*BaseResolution, *ImageInfo) {
	res := &BaseResolution{Ref: baseRef}

	if baseRef == "" {
		res.Reason = "no FROM reference could be resolved from the Dockerfile"
		return res, nil
	}
	// FROM scratch is Docker's empty base, not an image to fetch: it
	// contributes no layers, so every layer belongs to the Dockerfile.
	if IsScratch(baseRef) {
		res.Confident = true
		return res, nil
	}

	ref := baseRef
	if digestOverride != "" {
		ref = pinToDigest(baseRef, digestOverride)
		res.Ref = ref
	}

	// A base image built locally (FROM an image that was never pushed) is
	// read from the local image store, as for the image being scanned.
	//
	// The bound covers this call and the ConfigFile read just below — the
	// only two places this function (or its caller) ever touches info.Image —
	// never anything the caller does with the returned ImageInfo afterward.
	rctx, cancel := WithResolveTimeout(ctx)
	defer cancel()
	info, err := ResolveAny(rctx, ref, platform)
	if err != nil {
		res.Reason = fmt.Sprintf("could not fetch base image config for %s: %v", ref, err)
		return res, nil
	}
	res.Digest = info.Digest
	if digestOverride == "" {
		res.Ref = info.Ref // the pinned "name@digest" form (or the local tag, for a local base)
	}

	baseCF, err := info.Image.ConfigFile()
	if err != nil {
		res.Reason = fmt.Sprintf("could not read base image config for %s: %v", ref, err)
		_ = info.Close()
		return res, nil
	}

	count, err := BaseLayerCount(finalCF, baseCF)
	if err != nil {
		res.Reason = baseMismatchReason(err, digestOverride)
		_ = info.Close()
		return res, nil
	}

	res.LayerCount = count
	res.Confident = true
	return res, info
}

// ResolveBase is ResolveBaseImage for callers that only need the
// layer-boundary verdict, not the opened image (closed immediately here).
func ResolveBase(
	ctx context.Context,
	finalCF *v1.ConfigFile,
	baseRef string,
	digestOverride string,
	platform string,
) *BaseResolution {
	res, info := ResolveBaseImage(ctx, finalCF, baseRef, digestOverride, platform)
	_ = info.Close()
	return res
}

// IsScratch reports whether ref is Docker's reserved empty base image.
func IsScratch(ref string) bool {
	return strings.EqualFold(strings.TrimSpace(ref), "scratch")
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
