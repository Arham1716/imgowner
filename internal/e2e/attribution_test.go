//go:build e2e

// Package e2e validates the attribution pipeline against real images pulled
// from a registry. These tests need network access plus a Trivy binary, so
// they are gated behind the e2e build tag and excluded from `go test ./...`.
//
//	go test -tags e2e ./internal/e2e/...
package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/pipeline"
	"github.com/Arham1716/imgowner/internal/scan"
)

// baseImage is an image that is small, public and reliably carries a handful of
// known CVEs. The digest is intentionally not pinned: these tests assert
// structural properties of the attribution, never a specific CVE count.
const baseImage = "debian:12-slim"

func TestMain(m *testing.M) {
	if _, err := exec.LookPath("trivy"); err != nil {
		println("skipping e2e: trivy not found in PATH")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func trivyVersion(t *testing.T) string {
	t.Helper()
	v, err := scan.InstalledVersion(context.Background())
	if err != nil {
		t.Fatalf("resolving trivy version: %v", err)
	}
	return v
}

// writeDockerfile writes content to a temp Dockerfile and returns its path.
func writeDockerfile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Dockerfile")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing dockerfile: %v", err)
	}
	return path
}

func runAttribute(t *testing.T, imageRef, dockerfile, baseDigest string) *pipeline.AttributeResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	res, err := pipeline.Attribute(ctx, pipeline.AttributeRequest{
		ImageRef:       imageRef,
		DockerfilePath: dockerfile,
		BaseDigest:     baseDigest,
		Platform:       "linux/amd64",
		TrivyVersion:   trivyVersion(t),
		Timeout:        8 * time.Minute,
		BaseCandidates: 0, // recommendation is advisory; keep these tests fast
	})
	if err != nil {
		t.Fatalf("pipeline.Attribute: %v", err)
	}
	return res
}

// An image scanned against a Dockerfile declaring that same image as its base
// is entirely base: there are no layers above the base image to own anything.
// If this test fails, the core layer-prefix matching is broken.
func TestAttribute_ImageIsItsOwnBase(t *testing.T) {
	df := writeDockerfile(t, "FROM "+baseImage+"\n")
	res := runAttribute(t, baseImage, df, "")

	if !res.Base.Confident {
		t.Fatalf("base boundary should be verifiable when image == base, got: %s", res.Base.Reason)
	}

	counts := pipeline.OwnerCounts(res.Findings)
	t.Logf("findings=%d counts=%v", len(res.Findings), counts)

	if counts[attribution.OwnerAddedOS] != 0 {
		t.Errorf("image is unmodified, so nothing can be added-os; got %d", counts[attribution.OwnerAddedOS])
	}
	// Every finding that carried a usable layer DiffID must land on the base.
	attributed := len(res.Findings) - counts[attribution.OwnerUnattributed]
	if attributed > 0 && counts[attribution.OwnerBase] != attributed {
		t.Errorf("all layer-attributed findings should be base: base=%d attributed=%d",
			counts[attribution.OwnerBase], attributed)
	}
}

// Declaring an unrelated base must be detected, not silently absorbed. Before
// this was fixed the layer check failed quietly and every base CVE was
// reported as added-os.
func TestAttribute_UnrelatedBaseIsDetected(t *testing.T) {
	df := writeDockerfile(t, "FROM alpine:3.20\n")
	res := runAttribute(t, baseImage, df, "")

	if res.Base.Confident {
		t.Fatal("alpine must not validate as the base of a debian image")
	}
	if res.Base.Reason == "" {
		t.Error("an unverified base must explain why")
	}

	counts := pipeline.OwnerCounts(res.Findings)
	if len(res.Findings) > 0 && counts[attribution.OwnerUnattributed] != len(res.Findings) {
		t.Errorf("unverified base must yield only unattributed findings, got %v", counts)
	}
	for _, f := range res.Findings {
		if f.UnattributedReason == "" {
			t.Errorf("%s: unattributed finding is missing its reason", f.CVE)
			break
		}
	}
}

// Pinning the base to the digest actually under test must restore confidence,
// which is the documented remedy for a moved tag.
func TestAttribute_DigestPinRestoresConfidence(t *testing.T) {
	df := writeDockerfile(t, "FROM "+baseImage+"\n")

	// Resolve the digest of the image under test, then declare it explicitly.
	probe := runAttribute(t, baseImage, df, "")
	if probe.Digest == "" {
		t.Fatal("expected the scanned image to resolve to a digest")
	}

	res := runAttribute(t, baseImage, df, probe.Digest)
	if !res.Base.Confident {
		t.Fatalf("explicit digest pin should verify, got: %s", res.Base.Reason)
	}
}

// Every finding must carry a severity and a package name; downstream reports
// and the policy gate both depend on these being populated.
func TestAttribute_FindingsAreWellFormed(t *testing.T) {
	df := writeDockerfile(t, "FROM "+baseImage+"\n")
	res := runAttribute(t, baseImage, df, "")

	if len(res.Findings) == 0 {
		t.Skip("image currently reports no CVEs; nothing to validate")
	}
	for _, f := range res.Findings {
		if f.CVE == "" {
			t.Error("finding with empty CVE id")
		}
		if f.Package == "" {
			t.Errorf("%s: empty package name", f.CVE)
		}
		if f.Severity == "" {
			t.Errorf("%s: empty severity", f.CVE)
		}
		if f.Owner == "" {
			t.Errorf("%s: empty owner", f.CVE)
		}
	}
}
