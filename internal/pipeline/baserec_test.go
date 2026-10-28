package pipeline

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// push writes img to ref on the in-memory test registry.
func push(t *testing.T, ref string, img v1.Image) {
	t.Helper()
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatalf("parsing %s: %v", ref, err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatalf("pushing %s: %v", ref, err)
	}
}

func digestOf(t *testing.T, img v1.Image) string {
	t.Helper()
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d.String()
}

// installFakeTrivy puts a `trivy` stub on PATH that reports no vulnerability
// DB (so the scan cache is bypassed, see scan.DBStamp) and, for `trivy image
// ...<ref>`, prints the canned JSON registered for whichever digest the ref
// ends in. vulnJSON maps a digest ("sha256:...") to the Results JSON body.
func installFakeTrivy(t *testing.T, vulnJSON map[string]string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stub")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}
	dir := t.TempDir()
	var cases strings.Builder
	for digest, body := range vulnJSON {
		fmt.Fprintf(&cases, "  *%s*) cat <<'JSON'\n%s\nJSON\n  ;;\n", digest, body)
	}
	script := `#!/bin/sh
if [ "$1" = version ]; then
  echo '{"Version":"0.76.0"}'
  exit 0
fi
for a in "$@"; do ref="$a"; done
case "$ref" in
` + cases.String() + `  *) echo '{"SchemaVersion":2,"Results":[]}' ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "trivy"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// vulnResult renders one scan.Result (as Trivy's own JSON) naming the given
// CVE IDs, all on a single synthetic target.
func vulnResult(cves ...string) string {
	var vulns strings.Builder
	for i, c := range cves {
		if i > 0 {
			vulns.WriteString(",")
		}
		fmt.Fprintf(&vulns, `{"VulnerabilityID":%q,"PkgName":"pkg","Severity":"HIGH"}`, c)
	}
	return fmt.Sprintf(`{"SchemaVersion":2,"Results":[{"Target":"t","Class":"os-pkgs","Vulnerabilities":[%s]}]}`, vulns.String())
}

// The acceptance-test finding this fixes: base-image recommendation compared
// candidates against the FINAL image's scan, which also carries every CVE
// from the app/added-os layers. A candidate that happens not to have those
// too was then credited with "removing" them, when switching the base can
// never touch a CVE that isn't in the base to start with.
//
// Fixture: a 1-layer base image (one CVE, CVE-BASE-1), a final image built
// by appending one more layer on top (contributing CVE-APP-1), and a newer
// base tag with 0 CVEs. With the bug, CVEsRemoved would be 2 (both CVEs,
// since the candidate has neither); fixed, it must be 1 (only CVE-BASE-1,
// the only one that ever belonged to the base).
func TestAttribute_BaseRecommendation_CountsOnlyBaseImageCVEs(t *testing.T) {
	baseImg, err := random.Image(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	extraLayer, err := random.Layer(128, types.DockerLayer)
	if err != nil {
		t.Fatal(err)
	}
	finalImg, err := mutate.AppendLayers(baseImg, extraLayer)
	if err != nil {
		t.Fatal(err)
	}
	candidateImg, err := random.Image(128, 1) // a different, "fixed" base image

	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	baseRepo := host + "/fixture/base"
	finalRepo := host + "/fixture/final"

	push(t, baseRepo+":1.0-slim", baseImg)
	push(t, baseRepo+":1.1-slim", candidateImg) // the only enumerable candidate
	push(t, finalRepo+":build", finalImg)

	installFakeTrivy(t, map[string]string{
		digestOf(t, baseImg):      vulnResult("CVE-BASE-1"),
		digestOf(t, finalImg):     vulnResult("CVE-BASE-1", "CVE-APP-1"),
		digestOf(t, candidateImg): vulnResult(), // the candidate fixes everything
	})

	dir := t.TempDir()
	dockerfilePath := filepath.Join(dir, "Dockerfile")
	dockerfile := fmt.Sprintf("FROM %s:1.0-slim\nRUN echo hi\n", baseRepo)
	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Attribute(context.Background(), AttributeRequest{
		ImageRef:       finalRepo + ":build",
		DockerfilePath: dockerfilePath,
		TrivyVersion:   "0.76.0",
		BaseCandidates: 5,
	})
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if !res.Base.Confident {
		t.Fatalf("base layer boundary not confidently resolved: %+v", res.Base)
	}
	if len(res.Candidates) != 1 {
		t.Fatalf("want 1 enumerable candidate (1.1-slim), got %+v", res.Candidates)
	}
	c := res.Candidates[0]
	if c.Failed {
		t.Fatalf("candidate scan failed: %s", c.FailReason)
	}
	if c.CVEsRemoved != 1 {
		t.Errorf("CVEsRemoved = %d, want 1 (CVE-BASE-1 only; CVE-APP-1 is an app-layer "+
			"CVE that no base-image switch could ever remove, and must not be counted)", c.CVEsRemoved)
	}
	if c.CVEsRemaining != 0 {
		t.Errorf("CVEsRemaining = %d, want 0", c.CVEsRemaining)
	}
}

// A base resolved without --base-digest must still carry its resolved
// digest (previously empty unless --base-digest was passed), so a report
// can show exactly which base image was actually compared against.
func TestAttribute_BaseResolution_DigestPopulatedWithoutOverride(t *testing.T) {
	baseImg, err := random.Image(128, 1)
	if err != nil {
		t.Fatal(err)
	}
	finalImg, err := mutate.AppendLayers(baseImg, mustLayer(t))

	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	baseRepo := host + "/fixture/digest-base"
	finalRepo := host + "/fixture/digest-final"
	push(t, baseRepo+":1.0", baseImg)
	push(t, finalRepo+":build", finalImg)

	installFakeTrivy(t, map[string]string{
		digestOf(t, baseImg):  vulnResult(),
		digestOf(t, finalImg): vulnResult(),
	})

	dir := t.TempDir()
	dockerfilePath := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(fmt.Sprintf("FROM %s:1.0\n", baseRepo)), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Attribute(context.Background(), AttributeRequest{
		ImageRef:       finalRepo + ":build",
		DockerfilePath: dockerfilePath,
		TrivyVersion:   "0.76.0",
	})
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	want := digestOf(t, baseImg)
	if res.Base.Digest != want {
		t.Errorf("Base.Digest = %q, want %q (the base's own resolved digest)", res.Base.Digest, want)
	}
}

func mustLayer(t *testing.T) v1.Layer {
	t.Helper()
	l, err := random.Layer(128, types.DockerLayer)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
