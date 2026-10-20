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

	info, err := image.Resolve(ctx, req.ImageRef, req.Platform)
	if err != nil {
		return nil, err
	}

	runner := &scan.Runner{
		TrivyVersion: req.TrivyVersion,
		Platform:     req.Platform,
		Timeout:      req.Timeout,
	}
	result, err := runner.Scan(ctx, info.Ref, info.Digest)
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
	findings = attribution.MapToDockerfileLines(findings, layerMap)

	out := &AttributeResult{
		Findings: findings,
		Base:     base,
		BaseRef:  baseRef,
		Digest:   info.Digest,
		Scan:     result,
	}

	// Recommendation is advisory; a registry failure here must not lose the findings.
	if req.BaseCandidates > 0 && base.Confident {
		out.Candidates, _ = baserec.Recommend(ctx, baseRef, result, runner, req.Platform, req.BaseCandidates)
	}

	return out, nil
}

// OwnerCounts tallies findings by owner, for summaries and assertions.
func OwnerCounts(findings []attribution.Finding) map[attribution.Owner]int {
	counts := make(map[attribution.Owner]int, 4)
	for _, f := range findings {
		counts[f.Owner]++
	}
	return counts
}
