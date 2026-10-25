package image

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// unreachableRef points at a closed local port, so the registry lookup fails
// fast with ErrRegistryUnreachable and the local fallback is exercised.
const unreachableRef = "127.0.0.1:1/acc/app:local"

// fakeDocker writes an image for arch to a tarball and installs a stub CLI
// that knows only that one image: `image inspect` succeeds for it and
// `image save -o <path>` copies the tarball there.
func fakeDocker(t *testing.T, arch string, known bool) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stub")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	img, err := random.Image(256, 2)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf.OS, cf.Architecture = "linux", arch
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatal(err)
	}
	tag, _ := name.NewTag(unreachableRef)
	src := filepath.Join(dir, "src.tar")
	if err := tarball.WriteToFile(src, tag, img); err != nil {
		t.Fatal(err)
	}
	inspect := "exit 1"
	if known {
		inspect = "exit 0"
	}
	script := `#!/bin/sh
case "$2" in
  inspect) ` + inspect + ` ;;
  save) cp "` + src + `" "$4" ;;
esac
`
	bin := filepath.Join(dir, "docker")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := localRuntimes
	localRuntimes = []string{bin}
	t.Cleanup(func() { localRuntimes = old })
}

func TestResolveAny_FallsBackToTheLocalImageStore(t *testing.T) {
	fakeDocker(t, "amd64", true)
	info, err := ResolveAny(context.Background(), unreachableRef, "linux/amd64")
	if err != nil {
		t.Fatalf("ResolveAny: %v", err)
	}
	if !info.Local || info.Archive == "" {
		t.Fatalf("want a local image with an archive, got %+v", info)
	}
	if _, err := os.Stat(info.Archive); err != nil {
		t.Fatalf("archive missing: %v", err)
	}
	if d, _ := info.Image.Digest(); d.String() != info.Digest {
		t.Errorf("digest %s does not match the image's own %s", info.Digest, d)
	}
	if err := info.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(info.Archive)); !os.IsNotExist(err) {
		t.Error("Close left the temporary archive behind")
	}
	if err := info.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// Without a local copy the registry's error is the one the user needs.
func TestResolveAny_NotLocalReturnsTheRegistryError(t *testing.T) {
	fakeDocker(t, "amd64", false)
	_, err := ResolveAny(context.Background(), unreachableRef, "linux/amd64")
	var unreachable *ErrRegistryUnreachable
	if !errors.As(err, &unreachable) {
		t.Fatalf("want ErrRegistryUnreachable, got %v", err)
	}
}

// Scanning an arm64 build as amd64 would report CVEs for binaries that are
// not in the image being asked about.
func TestResolveAny_RefusesALocalImageForAnotherPlatform(t *testing.T) {
	fakeDocker(t, "arm64", true)
	_, err := ResolveAny(context.Background(), unreachableRef, "linux/amd64")
	if err == nil {
		t.Fatal("an arm64 local image was accepted for linux/amd64")
	}
}

// A malformed reference never reaches the local fallback (or a CLI).
func TestResolveAny_InvalidReferenceIsRejected(t *testing.T) {
	if _, err := ResolveAny(context.Background(), "-rm:latest", ""); err == nil {
		t.Fatal("a reference starting with '-' was accepted")
	}
}

func TestCheckPlatform(t *testing.T) {
	img, _ := random.Image(64, 1)
	cf, _ := img.ConfigFile()
	cf.OS, cf.Architecture, cf.Variant = "linux", "arm", "v7"
	img, _ = mutate.ConfigFile(img, cf)
	for _, c := range []struct {
		platform string
		ok       bool
	}{{"", true}, {"linux/arm", true}, {"linux/arm/v7", true}, {"linux/arm/v6", false}, {"linux/amd64", false}} {
		if err := checkPlatform(img, c.platform); (err == nil) != c.ok {
			t.Errorf("checkPlatform(%q) = %v, want ok=%v", c.platform, err, c.ok)
		}
	}
	var _ v1.Image = img
}
