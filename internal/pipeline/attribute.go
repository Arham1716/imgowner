// Package pipeline composes the scan, layer-mapping and attribution steps into
// a single reusable flow so that every entry point — the attribute command, the
// ci command and the end-to-end tests — exercises exactly the same code path.
package pipeline

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/baserec"
	"github.com/Arham1716/imgowner/internal/dockerfile"
	"github.com/Arham1716/imgowner/internal/image"
	"github.com/Arham1716/imgowner/internal/scan"
)

// AttributeRequest holds everything the attribution flow needs.
type AttributeRequest struct {
	ImageRef       string
	DockerfilePath string
	BaseDigest     string // optional; pins the base image to its build-time digest
	Platform       string
	TrivyVersion   string
	Timeout        time.Duration
	BaseCandidates int // 0 disables base image recommendation
}

// AttributeResult is the outcome of the attribution flow.
type AttributeResult struct {
	Findings   []attribution.Finding
	Base       *image.BaseResolution
	BaseRef    string
	Candidates []baserec.Candidate
	Digest     string
	Scan       *scan.Result
	// Squashed is true when no finding carried a layer DiffID, which means the
	// image was flattened and per-layer attribution is impossible for any of them.
	Squashed bool
}

// Attribute resolves the image, scans it, maps its layers to the Dockerfile and
// classifies every finding by owner. Base image recommendation runs last and is
// best-effort: a failure there never fails the attribution itself.
func Attribute(ctx context.Context, req AttributeRequest) (*AttributeResult, error) {
	if req.ImageRef == "" {
		return nil, fmt.Errorf("pipeline: image reference is required")
	}
	if _, err := os.Stat(req.DockerfilePath); err != nil {
		return nil, fmt.Errorf("pipeline: dockerfile %s: %w", req.DockerfilePath, err)
	}

	info, err := image.ResolveAny(ctx, req.ImageRef, req.Platform)
	if err != nil {
		return nil, err
	}
	defer func() { _ = info.Close() }()

	runner := &scan.Runner{
		TrivyVersion: req.TrivyVersion,
		Platform:     req.Platform,
		Timeout:      req.Timeout,
	}
	result, err := scanImage(ctx, runner, info)
	if err != nil {
		return nil, err
	}

	df, err := dockerfile.Parse(req.DockerfilePath)
	if err != nil {
		return nil, err
	}
	finalStage := df.FinalStage()
	if finalStage == nil {
		return nil, fmt.Errorf("pipeline: dockerfile %s declares no stages", req.DockerfilePath)
	}

	imgCF, err := info.Image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("pipeline: reading image config: %w", err)
	}
	layerMap, err := image.BuildLayerMap(imgCF)
	if err != nil {
		return nil, err
	}

	baseRef := df.ResolveBaseRef(finalStage)
	base := image.ResolveBase(ctx, imgCF, baseRef, req.BaseDigest, req.Platform)

	findings := attribution.Classify(result.Results, layerMap, base)
	findings = attribution.MapToDockerfileLines(findings, layerMap, df)

	out := &AttributeResult{
		Findings: findings,
		Base:     base,
		BaseRef:  baseRef,
		Digest:   info.Digest,
		Scan:     result,
		Squashed: isSquashed(result),
	}

	// Recommendation is advisory; a registry failure here must not lose the findings.
	if req.BaseCandidates > 0 && base.Confident {
		out.Candidates, _ = baserec.Recommend(ctx, baseRef, result, runner, req.Platform, req.BaseCandidates)
	}

	return out, nil
}

// scanImage scans a registry image by reference, or a local image through
// the archive it was exported to.
func scanImage(ctx context.Context, runner *scan.Runner, info *image.ImageInfo) (*scan.Result, error) {
	if info.Local {
		return runner.ScanArchive(ctx, info.Archive, info.Digest)
	}
	return runner.Scan(ctx, info.Ref, info.Digest)
}

// ScanImage is scanImage for callers outside the package (the new_only
// baseline in the ci command).
func ScanImage(ctx context.Context, runner *scan.Runner, info *image.ImageInfo) (*scan.Result, error) {
	return scanImage(ctx, runner, info)
}

// isSquashed reports whether the scan produced vulnerabilities but none of them
// carried a layer DiffID. A flattened image has a single layer and no per-layer
// provenance, so every finding would otherwise be reported as unattributed with
// no explanation of the underlying cause.
func isSquashed(result *scan.Result) bool {
	if result == nil {
		return false
	}
	total := 0
	for _, t := range result.Results {
		for _, v := range t.Vulnerabilities {
			total++
			if v.Layer.DiffID != "" {
				return false
			}
		}
	}
	return total > 0
}

// OwnerCounts tallies findings by owner, for summaries and assertions.
func OwnerCounts(findings []attribution.Finding) map[attribution.Owner]int {
	counts := make(map[attribution.Owner]int, 4)
	for _, f := range findings {
		counts[f.Owner]++
	}
	return counts
}
