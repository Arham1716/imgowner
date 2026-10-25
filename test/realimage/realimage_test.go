//go:build realimage

// Package realimage validates the attribution pipeline, digest/layer
// reporting and pin lookup against real images this suite builds and pushes
// to a throwaway registry (FR-47..FR-50). It is project infrastructure (see
// requirements §3.1): it ships in no release artifact, and it needs docker,
// trivy, network access to pull public base images, and a registry
// reachable at REALIMAGE_REGISTRY (default localhost:5000), so it is gated
// behind the realimage build tag:
//
//	go test -tags realimage -timeout 20m ./test/realimage/...
//
// In CI the registry is a job-level service container pinned by digest (see
// .github/workflows/ci.yml). For a local run, start a throwaway one first:
//
//	docker run -d -p 5000:5000 registry:2
package realimage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/history"
	"github.com/Arham1716/imgowner/internal/pins"
)

var imgownerBin string

func TestMain(m *testing.M) {
	for _, bin := range []string{"docker", "trivy"} {
		if _, err := exec.LookPath(bin); err != nil {
			fmt.Printf("skipping realimage suite: %s not found in PATH\n", bin)
			os.Exit(0)
		}
	}

	addr := registryAddr()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fmt.Printf("skipping realimage suite: no registry reachable at %s (%v)\n"+
			"start a throwaway one with: docker run -d -p 5000:5000 registry:2\n", addr, err)
		os.Exit(0)
	}
	_ = conn.Close()

	bin := os.Getenv("IMGOWNER_BIN")
	if bin == "" {
		dir, err := os.MkdirTemp("", "imgowner-realimage-bin")
		if err != nil {
			fmt.Printf("creating temp dir: %v\n", err)
			os.Exit(2)
		}
		bin = filepath.Join(dir, "imgowner")
		cmd := exec.Command("go", "build", "-o", bin, "../../cmd/imgowner")
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			fmt.Printf("building imgowner binary: %v\n%s\n", err, out.String())
			os.Exit(2)
		}
	}
	imgownerBin = bin

	os.Exit(m.Run())
}

func registryAddr() string {
	if a := os.Getenv("REALIMAGE_REGISTRY"); a != "" {
		return a
	}
	return "localhost:5000"
}

// fixtureSpec describes one of the four real-image fixtures (FR-47).
// resolvePin is nil for the Python fixture: FR-50 (pin status check) only
// covers the three OS package managers.
type fixtureSpec struct {
	name       string
	baseRef    string // digest-pinned base, matching the fixture's own FROM line
	pkgManager string // "apt", "apk", "rpm", or "" for the Python fixture
	pkgName    string
	resolvePin func(t *testing.T, baseRef string) string
}

var fixtures = []fixtureSpec{
	{
		name:       "debian-apt",
		baseRef:    "debian:12-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8",
		pkgManager: "apt",
		pkgName:    "curl",
		resolvePin: resolveAptCandidate,
	},
	{
		name:       "alpine-apk",
		baseRef:    "alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
		pkgManager: "apk",
		pkgName:    "curl",
		resolvePin: resolveApkCandidate,
	},
	{
		name:       "rocky-dnf",
		baseRef:    "rockylinux:9@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6",
		pkgManager: "rpm",
		pkgName:    "wget",
		resolvePin: resolveDnfCandidate,
	},
	{
		// No resolvePin: PyPI never removes a published version, so the
		// pinned requests==2.32.3 in fixtures/python-pip/requirements.txt
		// never goes stale the way an apt/apk/dnf version literal would.
		// baseRef is still needed: FR-49's base-layer check applies to all
		// four fixtures, not just the three with a pin to resolve.
		name:    "python-pip",
		baseRef: "python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704",
	},
}

func TestRealImage(t *testing.T) {
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			testFixture(t, f)
		})
	}
}

func testFixture(t *testing.T, f fixtureSpec) {
	var pin string
	if f.resolvePin != nil {
		pin = f.resolvePin(t, f.baseRef)
		t.Logf("resolved %s pin for %s: %s", f.pkgManager, f.pkgName, pin)
	}

	ctxDir, dfPath := prepareBuildContext(t, f, pin)
	ref := fmt.Sprintf("%s/imgowner-fixtures/%s:test", registryAddr(), f.name)
	buildAndPush(t, ctxDir, dfPath, ref)

	// FR-47: run the real binary (built in TestMain) and real Trivy against
	// the image this test just pushed.
	// Each fixture gets its own history directory (via --config) so the
	// FR-31 assertions below see exactly the records this test produced.
	histDir := t.TempDir()
	cfgPath := writeHistoryConfig(t, histDir)

	out := runImgowner(t, "--config", cfgPath, "attribute", "--image", ref, "--dockerfile", dfPath,
		"--format", "json", "--base-candidates", "0")

	var report struct {
		Digest   string                `json:"digest"`
		BaseRef  string                `json:"base_ref"`
		Findings []attribution.Finding `json:"findings"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("parsing attribute JSON output: %v\nraw: %s", err, out)
	}

	assertHistoryRecord(t, histDir, report.Digest, report.Findings) // FR-31
	assertNoHistoryOnToolError(t, cfgPath, histDir, dfPath)         // FR-31: exit 2 records nothing
	assertDigestAndLayers(t, ref, report.Digest, report.Findings)   // FR-48
	assertAttribution(t, f, dfPath, report.Findings)                // FR-49

	if f.pkgManager != "" {
		assertPin(t, f, dfPath, cfgPath) // FR-50
		assertPinsHistory(t, histDir)    // FR-31
	}
}

// ── build context preparation ───────────────────────────────────────────────

func prepareBuildContext(t *testing.T, f fixtureSpec, pin string) (ctxDir, dfPath string) {
	t.Helper()
	srcDir := filepath.Join("fixtures", f.name)

	data, err := os.ReadFile(filepath.Join(srcDir, "Dockerfile"))
	if err != nil {
		t.Fatalf("reading fixture Dockerfile: %v", err)
	}
	content := string(data)
	hasPlaceholder := strings.Contains(content, "__PIN__")
	if hasPlaceholder && pin == "" {
		t.Fatalf("fixture %s has a __PIN__ placeholder but no pin was resolved", f.name)
	}
	if !hasPlaceholder && pin != "" {
		t.Fatalf("fixture %s resolved a pin %q but its Dockerfile has no __PIN__ placeholder", f.name, pin)
	}
	if hasPlaceholder {
		content = strings.ReplaceAll(content, "__PIN__", pin)
	}

	dir := t.TempDir()
	dfPath = filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(dfPath, []byte(content), 0o644); err != nil {
		t.Fatalf("writing resolved Dockerfile: %v", err)
	}

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatalf("reading fixture dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "Dockerfile" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(srcDir, e.Name()))
		if err != nil {
			t.Fatalf("reading fixture file %s: %v", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644); err != nil {
			t.Fatalf("copying fixture file %s: %v", e.Name(), err)
		}
	}
	return dir, dfPath
}

// ── pin resolution ───────────────────────────────────────────────────────────
//
// Each of the three OS package repos keeps only the latest build of a
// package per release branch, so a version literal baked into a fixture
// would eventually stop being installable. These resolve the real current
// version from the base image's own repo at test time instead.

func resolveAptCandidate(t *testing.T, baseRef string) string {
	const script = `apt-get update -qq >/dev/null 2>&1; apt-cache policy curl | awk '/Candidate:/{print $2}'`
	out := strings.TrimSpace(dockerRunCapture(t, baseRef, script))
	if out == "" || out == "(none)" {
		t.Fatalf("could not resolve an apt candidate version for curl")
	}
	return out
}

func resolveApkCandidate(t *testing.T, baseRef string) string {
	const script = `apk update -q >/dev/null 2>&1; apk policy curl | awk 'NR==2{gsub(/^[ \t]+/,""); gsub(/:$/,""); print}'`
	out := strings.TrimSpace(dockerRunCapture(t, baseRef, script))
	if out == "" {
		t.Fatalf("could not resolve an apk candidate version for curl")
	}
	return out
}

func resolveDnfCandidate(t *testing.T, baseRef string) string {
	const script = `dnf -q --setopt=timeout=15 --setopt=retries=2 list wget 2>/dev/null | awk '$1 ~ /^wget\./{print $2}' | tail -1`
	out := strings.TrimSpace(dockerRunCapture(t, baseRef, script))
	if out == "" {
		t.Fatalf("could not resolve a dnf candidate version for wget")
	}
	return out
}

func dockerRunCapture(t *testing.T, imageRef, script string) string {
	t.Helper()
	// Resolving a version runs a package manager against the distribution's
	// public mirrors, and one of them can stall for minutes (a real CI run lost
	// five to a single slow Rocky mirror). A stalled attempt is cheap to abandon
	// and a fresh one usually lands on a different mirror, so: three attempts,
	// each capped well below the job's budget, rather than one long wait.
	const attempts = 3
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--entrypoint", "sh", imageRef, "-c", script)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		cancel()
		if err == nil {
			return stdout.String()
		}
		lastErr = fmt.Errorf("%w; stderr: %s", err, strings.TrimSpace(stderr.String()))
		t.Logf("docker run %s failed (attempt %d of %d): %v", imageRef, attempt, attempts, lastErr)
	}
	t.Fatalf("docker run %s failed after %d attempts: %v", imageRef, attempts, lastErr)
	return ""
}

// ── build, push, run ─────────────────────────────────────────────────────────

func buildAndPush(t *testing.T, ctxDir, dockerfilePath, ref string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// --provenance=false --sbom=false: without them, BuildKit pushes a
	// multi-manifest image index (the image plus an attestation manifest),
	// and the registry's own manifest digest for the tag is then the index's
	// digest, not the single-platform image digest go-containerregistry
	// resolves and imgowner reports. Disabling both keeps the pushed
	// manifest flat so the two are directly comparable (FR-48).
	build := exec.CommandContext(ctx, "docker", "build",
		"--provenance=false", "--sbom=false", "-f", dockerfilePath, "-t", ref, ctxDir)
	runOrFatal(t, build, "docker build")

	push := exec.CommandContext(ctx, "docker", "push", ref)
	runOrFatal(t, push, "docker push")
}

func runOrFatal(t *testing.T, cmd *exec.Cmd, what string) {
	t.Helper()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s failed: %v\n%s", what, err, out.String())
	}
}

func runImgowner(t *testing.T, args ...string) []byte {
	t.Helper()
	out, _ := runImgownerStderr(t, args...)
	return out
}

// runImgownerStderr is runImgowner that also hands back what the binary
// wrote to stderr, for callers that need to know whether it warned.
func runImgownerStderr(t *testing.T, args ...string) (stdout, stderr []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, imgownerBin, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outBuf, &errBuf
	err := cmd.Run()
	// imgowner warns on stderr for non-fatal conditions (e.g. a pin lookup
	// container failing) and still exits 0; surface it either way so a
	// resulting "status is unknown" assertion failure isn't a dead end.
	if errBuf.Len() > 0 {
		t.Logf("imgowner %v stderr:\n%s", args, errBuf.String())
	}
	if err != nil {
		t.Fatalf("imgowner %v: %v", args, err)
	}
	return outBuf.Bytes(), errBuf.Bytes()
}

func captureJSON(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v: %v\nstderr: %s", name, args, err, stderr.String())
	}
	return stdout.String()
}

// ── independent digest / layer computation (FR-48) ──────────────────────────

func registryManifestDigest(t *testing.T, ref string) string {
	t.Helper()
	out := captureJSON(t, "docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest}}")
	var m struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("parsing imagetools manifest JSON: %v\nraw: %s", err, out)
	}
	if m.Digest == "" {
		t.Fatalf("registry manifest for %s has no digest: %s", ref, out)
	}
	return m.Digest
}

// registryDiffIDs returns ref's layer DiffIDs as recorded in its config, read
// straight from the registry. The base images (debian/alpine/rockylinux/
// python on Docker Hub) are published as multi-platform image indexes, and
// imagetools inspect's .Image field is empty for an index ref -- there is no
// single config to return until a platform is chosen. amd64PlatformRef
// resolves the ref down to its linux/amd64 child manifest first, which is
// also what imgowner itself scans (platform defaults to linux/amd64). Our own
// pushed fixtures are already flat single-platform manifests (built with
// --provenance=false --sbom=false), so this is a no-op for them.
func registryDiffIDs(t *testing.T, ref string) []string {
	t.Helper()
	ref = amd64PlatformRef(t, ref)
	out := captureJSON(t, "docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Image}}")
	var cfg struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("parsing imagetools image config JSON for %s: %v\nraw: %s", ref, err, out)
	}
	if len(cfg.RootFS.DiffIDs) == 0 {
		t.Fatalf("no diff_ids resolved for %s (raw image JSON: %s)", ref, out)
	}
	return cfg.RootFS.DiffIDs
}

// amd64PlatformRef returns ref unchanged if it already names a single
// manifest, or the repository@digest of its linux/amd64 child if ref names a
// multi-platform index. Decoding {{json .Manifest}} as plain JSON (rather
// than templating over .Manifest.Manifests directly) avoids a hard template
// error: an index and a single manifest are different underlying Go types in
// buildx's template data, and ranging over .Manifests on a plain manifest
// fails evaluation instead of yielding an empty range.
func amd64PlatformRef(t *testing.T, ref string) string {
	t.Helper()
	raw := captureJSON(t, "docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest}}")
	var m struct {
		MediaType string `json:"mediaType"`
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("parsing imagetools manifest JSON for %s: %v\nraw: %s", ref, err, raw)
	}
	if !strings.Contains(m.MediaType, "index") && !strings.Contains(m.MediaType, "manifest.list") {
		return ref // single manifest already; nothing to resolve.
	}
	for _, c := range m.Manifests {
		if c.Platform.OS == "linux" && c.Platform.Architecture == "amd64" {
			return repoName(ref) + "@" + c.Digest
		}
	}
	t.Fatalf("index %s has no linux/amd64 manifest: %s", ref, raw)
	return ""
}

// repoName strips a trailing "@sha256:..." or ":tag" from ref, leaving the
// bare repository path. A registry address can itself contain ':' (a port),
// so only a ':' after the last '/' is treated as a tag separator.
func repoName(ref string) string {
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		return ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i >= 0 && i > strings.LastIndex(ref, "/") {
		return ref[:i]
	}
	return ref
}

func localDiffIDs(t *testing.T, ref string) []string {
	t.Helper()
	out := captureJSON(t, "docker", "image", "inspect", ref, "--format", "{{json .RootFS.Layers}}")
	var ids []string
	if err := json.Unmarshal([]byte(out), &ids); err != nil {
		t.Fatalf("parsing docker image inspect RootFS.Layers: %v\nraw: %s", err, out)
	}
	return ids
}

func assertDigestAndLayers(t *testing.T, ref, reportedDigest string, findings []attribution.Finding) {
	t.Helper()

	wantDigest := registryManifestDigest(t, ref)
	if reportedDigest != wantDigest {
		t.Errorf("digest mismatch: imgowner reported %s, the registry reports %s", reportedDigest, wantDigest)
	}

	// Two independent sources -- the registry (via buildx/containerd) and the
	// local container runtime (via the Docker engine) -- must agree with
	// each other before either is trusted as ground truth for the findings
	// check below.
	fromRegistry := registryDiffIDs(t, ref)
	fromRuntime := localDiffIDs(t, ref)
	if !equalStrings(fromRegistry, fromRuntime) {
		t.Fatalf("registry and container runtime disagree on layer DiffIDs:\nregistry: %v\nruntime:  %v",
			fromRegistry, fromRuntime)
	}

	known := make(map[string]bool, len(fromRegistry))
	for _, id := range fromRegistry {
		known[id] = true
	}
	for _, f := range findings {
		if f.LayerDiffID == "" {
			continue
		}
		if !known[f.LayerDiffID] {
			t.Errorf("finding %s: reported layer DiffID %s is not one of the image's actual layers %v",
				f.CVE, f.LayerDiffID, fromRegistry)
		}
	}
}

// ── attribution invariants (FR-49) ──────────────────────────────────────────

func assertAttribution(t *testing.T, f fixtureSpec, dfPath string, findings []attribution.Finding) {
	t.Helper()

	var installLine int
	if f.pkgManager != "" {
		installLine = findInstallLine(t, dfPath, f.pkgManager)
	}

	baseDiffIDs := make(map[string]bool)
	for _, id := range registryDiffIDs(t, f.baseRef) {
		baseDiffIDs[id] = true
	}

	unattributed := 0
	for _, fd := range findings {
		switch fd.Owner {
		case attribution.OwnerUnattributed:
			unattributed++
			t.Logf("unattributed: %s %s (%s)", fd.CVE, fd.Package, fd.UnattributedReason)

		case attribution.OwnerAddedOS:
			if f.pkgManager == "" {
				continue // Python fixture: no OS install layer to map to.
			}
			if fd.Instruction == nil || fd.Instruction.Line != installLine {
				t.Errorf("finding %s: added-os should map to Dockerfile line %d, got %+v",
					fd.CVE, installLine, fd.Instruction)
			}

		case attribution.OwnerBase:
			if fd.LayerDiffID == "" || !baseDiffIDs[fd.LayerDiffID] {
				t.Errorf("finding %s: base finding's DiffID %q is not in the base image's layer list",
					fd.CVE, fd.LayerDiffID)
			}
		}
	}

	// Every fixture's base is pinned by the exact digest named in its own
	// FROM line, so the base boundary must always resolve confidently; zero
	// unattributed findings is the directly observable consequence.
	if unattributed != 0 {
		t.Errorf("expected 0 unattributed findings with a digest-pinned base, got %d", unattributed)
	}
}

func findInstallLine(t *testing.T, dfPath, pkgManager string) int {
	t.Helper()
	var needle string
	switch pkgManager {
	case "apt":
		needle = "apt-get install"
	case "apk":
		needle = "apk add"
	case "rpm":
		needle = "dnf install"
	default:
		return 0
	}
	data, err := os.ReadFile(dfPath)
	if err != nil {
		t.Fatalf("reading resolved Dockerfile: %v", err)
	}
	for i, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	t.Fatalf("no line containing %q found in %s", needle, dfPath)
	return 0
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── pin status check (FR-50) ─────────────────────────────────────────────────

func assertPin(t *testing.T, f fixtureSpec, dfPath, cfgPath string) {
	t.Helper()
	var out []byte
	var pinList []pins.Pin
	// The lookup runs a package manager against the distribution's public
	// mirrors, which can stall for reasons that have nothing to do with
	// imgowner (a real CI run lost five minutes to one slow Rocky mirror). When
	// -- and only when -- imgowner itself reports that the lookup failed, try
	// once more. A wrong answer, a bad offset or a status that is simply
	// wrong is never retried.
	for attempt := 1; ; attempt++ {
		var stderr []byte
		out, stderr = runImgownerStderr(t, "--config", cfgPath, "pins", "check", "--dockerfile", dfPath, "--format", "json")
		pinList = nil
		if err := json.Unmarshal(out, &pinList); err != nil {
			t.Fatalf("parsing pins check JSON output: %v\nraw: %s", err, out)
		}
		if attempt == 3 || !bytes.Contains(stderr, []byte("pin version lookup")) {
			break
		}
		t.Logf("pin lookup reported a failure (attempt %d of 3); retrying", attempt)
	}

	var found *pins.Pin
	for i := range pinList {
		if pinList[i].Package == f.pkgName {
			found = &pinList[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("pins check did not report a pin for %q; got %+v", f.pkgName, pinList)
	}
	if found.Manager != f.pkgManager {
		t.Errorf("pin manager = %q, want %q", found.Manager, f.pkgManager)
	}

	dfBytes, err := os.ReadFile(dfPath)
	if err != nil {
		t.Fatalf("reading resolved Dockerfile: %v", err)
	}
	end := found.ByteOffset + len(found.Version)
	if found.ByteOffset < 0 || end > len(dfBytes) {
		t.Fatalf("pin byte offset %d (len %d) out of bounds for a %d-byte file",
			found.ByteOffset, len(found.Version), len(dfBytes))
	}
	if got := string(dfBytes[found.ByteOffset:end]); got != found.Version {
		t.Errorf("pin byte offset points at %q, not the reported version %q", got, found.Version)
	}

	if found.Status == pins.StatusUnknown {
		t.Errorf("pin status is %q; a real package index lookup against a live base image should resolve a real status", found.Status)
	}
}

// ── scan history (FR-31) ─────────────────────────────────────────────────────

func writeHistoryConfig(t *testing.T, histDir string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".imgowner.yaml")
	// Single-quoted YAML scalar: no escape processing, so a Windows path with
	// backslashes survives when the suite is run locally.
	cfg := "history:\n  dir: '" + strings.ReplaceAll(histDir, "'", "''") + "'\n" +
		// A bounded lookup (the product default is 5m) so three attempts fit the job.
		"pins:\n  lookup_timeout: 150s\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func listHistory(t *testing.T, dir string) []history.Summary {
	t.Helper()
	store, err := history.Open(dir)
	if err != nil {
		t.Fatalf("opening history store: %v", err)
	}
	sums, skipped, err := store.List()
	if err != nil || skipped != 0 {
		t.Fatalf("listing history: skipped=%d err=%v", skipped, err)
	}
	return sums
}

// A successful attribute run leaves exactly one record whose digest and
// per-owner counts match what the run itself reported.
func assertHistoryRecord(t *testing.T, dir, reportedDigest string, findings []attribution.Finding) {
	t.Helper()
	sums := listHistory(t, dir)
	if len(sums) != 1 {
		t.Fatalf("expected exactly 1 history record after one attribute run, got %d", len(sums))
	}
	s := sums[0]
	if s.Command != "attribute" || s.Digest != reportedDigest {
		t.Errorf("record = %s/%s, want attribute/%s", s.Command, s.Digest, reportedDigest)
	}
	want := map[string]int{}
	for _, f := range findings {
		want[string(f.Owner)]++
	}
	for owner, n := range want {
		if s.Counts[owner] != n {
			t.Errorf("history counts[%s] = %d, the run reported %d", owner, s.Counts[owner], n)
		}
	}
	total := 0
	for _, n := range s.Counts {
		total += n
	}
	if total != len(findings) {
		t.Errorf("history counts sum to %d, the run reported %d findings", total, len(findings))
	}
}

// A run that exits 2 (here: an image that doesn't exist) writes no record.
func assertNoHistoryOnToolError(t *testing.T, cfgPath, histDir, dfPath string) {
	t.Helper()
	before := len(listHistory(t, histDir))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, imgownerBin, "--config", cfgPath, "attribute",
		"--image", registryAddr()+"/imgowner-fixtures/does-not-exist:nope",
		"--dockerfile", dfPath, "--format", "json", "--base-candidates", "0")
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 2 {
		t.Fatalf("attribute on a missing image should exit 2, got %v", err)
	}
	if after := len(listHistory(t, histDir)); after != before {
		t.Errorf("a failed run must not record history: %d records before, %d after", before, after)
	}
}

// After the attribute run and the pins check, the store holds both.
func assertPinsHistory(t *testing.T, dir string) {
	t.Helper()
	var sawPins bool
	for _, s := range listHistory(t, dir) {
		if s.Command == "pins-check" {
			sawPins = true
			if len(s.PinStatuses) == 0 {
				t.Errorf("the pins-check record carries no pin statuses: %+v", s)
			}
		}
	}
	if !sawPins {
		t.Error("pins check ran but left no pins-check history record")
	}
}
