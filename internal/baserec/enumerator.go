package baserec

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Candidate is one base image tag that may remove CVEs relative to the current base.
type Candidate struct {
	Ref           string // digest-pinned FROM argument, e.g. python:3.12.1-slim@sha256:...
	Tag           string // short tag, e.g. 3.12.1-slim
	Digest        string
	CVEsRemoved   int
	CVEsRemaining int
	Failed        bool   // true if the scan for this candidate failed
	FailReason    string
}

// Enumerate lists up to maxN patch-tag candidates for baseRef from the registry.
// Candidates share the same image name and variant suffix as the current tag,
// and have a higher semver version component (FR-09).
func Enumerate(ctx context.Context, baseRef string, maxN int) ([]string, error) {
	ref, err := name.ParseReference(baseRef)
	if err != nil {
		return nil, fmt.Errorf("baserec: parsing base ref %q: %w", baseRef, err)
	}

	currentTag := ref.Identifier() // e.g. "3.12-slim" or "1.25-alpine"
	repo := ref.Context()

	tags, err := remote.List(repo,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if err != nil {
		return nil, fmt.Errorf("baserec: listing tags for %s: %w", repo.Name(), err)
	}

	candidates := filterCandidates(currentTag, tags)

	// Newest patch versions first; cap at maxN.
	sort.Slice(candidates, func(i, j int) bool {
		return versionGt(candidates[i], candidates[j], currentTag)
	})
	if len(candidates) > maxN {
		candidates = candidates[:maxN]
	}

	// Return as fully-qualified references.
	refs := make([]string, len(candidates))
	for i, t := range candidates {
		refs[i] = fmt.Sprintf("%s:%s", repo.Name(), t)
	}
	return refs, nil
}

// filterCandidates returns tags that share the same variant suffix as currentTag
// and have a higher semver version.
func filterCandidates(currentTag string, allTags []string) []string {
	curVer, curSuffix := splitTagVariant(currentTag)
	curParts := parseSemver(curVer)

	var out []string
	for _, t := range allTags {
		if t == currentTag {
			continue
		}
		ver, suffix := splitTagVariant(t)
		if suffix != curSuffix {
			continue
		}
		parts := parseSemver(ver)
		if semverGt(parts, curParts) {
			out = append(out, t)
		}
	}
	return out
}

// splitTagVariant splits "3.12-slim" → ("3.12", "slim"), "1.25-alpine" → ("1.25","alpine"),
// "3.12.1-slim" → ("3.12.1","slim"), "latest" → ("latest","").
func splitTagVariant(tag string) (version, suffix string) {
	idx := strings.Index(tag, "-")
	if idx < 0 {
		return tag, ""
	}
	return tag[:idx], tag[idx+1:]
}

// parseSemver parses "3.12.1" or "3.12" into [major, minor, patch].
func parseSemver(v string) [3]int {
	var parts [3]int
	segments := strings.SplitN(v, ".", 3)
	for i, s := range segments {
		if i >= 3 {
			break
		}
		fmt.Sscanf(s, "%d", &parts[i])
	}
	return parts
}

// semverGt returns true if a > b.
func semverGt(a, b [3]int) bool {
	for i := range a {
		if a[i] > b[i] {
			return true
		}
		if a[i] < b[i] {
			return false
		}
	}
	return false
}

// versionGt compares two tags by semver (for sorting candidates newest-first).
func versionGt(tagA, tagB, _ string) bool {
	verA, _ := splitTagVariant(tagA)
	verB, _ := splitTagVariant(tagB)
	return semverGt(parseSemver(verA), parseSemver(verB))
}
