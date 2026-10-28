package baserec

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/Arham1716/imgowner/internal/image"
	"github.com/Arham1716/imgowner/internal/scan"
)

const maxConcurrency = 3 // FR-10, NFR-08

// Recommend scans up to maxN patch-tag candidates for baseRef in parallel
// (concurrency capped at 3), diffs their CVE sets against baseScan, and
// returns candidates sorted by CVEs removed descending (FR-09, FR-10, FR-11).
//
// baseScan must be a scan of the current base image itself, at the exact
// digest the final image was built from — never a scan of the final image.
// The final image also carries every CVE from the layers added on top of the
// base (added-os, app), which no base-image switch can ever remove; passing
// it here would count those as "removed" by every candidate that happens not
// to have them, inflating CVEsRemoved for reasons unrelated to the base.
func Recommend(
	ctx context.Context,
	baseRef string,
	baseScan *scan.Result,
	runner *scan.Runner,
	platform string,
	maxN int,
) ([]Candidate, error) {
	candidateRefs, err := Enumerate(ctx, baseRef, maxN)
	if err != nil {
		return nil, fmt.Errorf("baserec: enumerating candidates: %w", err)
	}
	if len(candidateRefs) == 0 {
		return nil, nil
	}

	baseCVEs := cveSet(baseScan)

	results := make([]Candidate, len(candidateRefs))
	for i, ref := range candidateRefs {
		results[i] = Candidate{Tag: tagFromRef(ref)}
	}

	// Bounded parallel scanning via errgroup + semaphore channel (FR-10, NFR-08).
	sem := make(chan struct{}, maxConcurrency)
	g, gctx := errgroup.WithContext(ctx)

	for i, ref := range candidateRefs {
		i, ref := i, ref
		g.Go(func() error {
			sem <- struct{}{}
			defer func() { <-sem }()

			// NFR-01: bound the metadata fetch; the scan just below has its
			// own bound via runner.Timeout.
			rctx, cancel := image.WithResolveTimeout(gctx)
			info, err := image.Resolve(rctx, ref, platform)
			cancel()
			if err != nil {
				results[i].Failed = true
				results[i].FailReason = err.Error()
				return nil // partial failure — continue other candidates (F8 DEFER)
			}
			results[i].Ref = fmt.Sprintf("%s@%s", taggedName(ref), info.Digest)
			results[i].Digest = info.Digest

			candidateScan, err := runner.Scan(gctx, info.Ref, info.Digest)
			if err != nil {
				results[i].Failed = true
				results[i].FailReason = err.Error()
				return nil
			}

			candidateCVEs := cveSet(candidateScan)
			removed := 0
			for cve := range baseCVEs {
				if !candidateCVEs[cve] {
					removed++
				}
			}
			results[i].CVEsRemoved = removed
			results[i].CVEsRemaining = len(candidateCVEs)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Sort: most CVEs removed first; failed candidates last.
	sortCandidates(results)
	return results, nil
}

// cveSet builds a set of CVE IDs from a scan result.
func cveSet(r *scan.Result) map[string]bool {
	s := make(map[string]bool)
	if r == nil {
		return s
	}
	for _, target := range r.Results {
		for _, v := range target.Vulnerabilities {
			s[v.VulnerabilityID] = true
		}
	}
	return s
}

// sortCandidates sorts in-place: most CVEs removed first, failed last.
func sortCandidates(cs []Candidate) {
	// Simple insertion sort — list is at most 5 elements.
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0; j-- {
			if candidateGt(cs[j], cs[j-1]) {
				cs[j], cs[j-1] = cs[j-1], cs[j]
			} else {
				break
			}
		}
	}
}

func candidateGt(a, b Candidate) bool {
	if a.Failed != b.Failed {
		return !a.Failed // non-failed > failed
	}
	return a.CVEsRemoved > b.CVEsRemoved
}

// tagFromRef extracts the tag portion of an image reference.
func tagFromRef(ref string) string {
	if idx := strings.LastIndex(ref, ":"); idx >= 0 {
		return ref[idx+1:]
	}
	return ref
}

// taggedName returns the ref without a digest suffix (for building pinned refs).
func taggedName(ref string) string {
	if idx := strings.Index(ref, "@"); idx >= 0 {
		return ref[:idx]
	}
	return ref
}
