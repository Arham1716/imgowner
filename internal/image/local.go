package image

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/Arham1716/imgowner/internal/safeio"
)

// localRuntimes are the container CLIs whose local image store is consulted,
// in order. Overridden in tests.
var localRuntimes = []string{"docker", "podman"}

// ResolveAny resolves imageRef from its registry and, only when the registry
// cannot serve it (not found, credentials refused, unreachable), from the
// local Docker or Podman image store. That is the common CI shape: build an
// image with `docker build -t myapp:$SHA .` and scan it before any push.
//
// The registry stays the source of truth: a tag that exists in both places is
// always read from the registry, so a stale local copy never shadows it. A
// local image is exported once to a temporary archive that both imgowner and
// Trivy read, so they see identical bytes; the caller must Close the result.
func ResolveAny(ctx context.Context, imageRef, platform string) (*ImageInfo, error) {
	info, remoteErr := Resolve(ctx, imageRef, platform)
	if remoteErr == nil {
		return info, nil
	}
	if !fallsBackToLocal(remoteErr) {
		return nil, remoteErr
	}
	local, err := resolveLocal(ctx, imageRef, platform)
	if err != nil {
		if errors.Is(err, errNotLocal) {
			return nil, remoteErr // the registry's answer is the useful one
		}
		return nil, fmt.Errorf("%w (and reading the local image failed: %v)", remoteErr, err)
	}
	return local, nil
}

// fallsBackToLocal reports whether a registry failure means "the registry
// doesn't have it for us" rather than a malformed request.
func fallsBackToLocal(err error) bool {
	var nf *ErrImageNotFound
	var auth *ErrRegistryAuth
	var unreachable *ErrRegistryUnreachable
	return errors.As(err, &nf) || errors.As(err, &auth) || errors.As(err, &unreachable)
}

var errNotLocal = errors.New("image is not in a local image store")

func resolveLocal(ctx context.Context, imageRef, platform string) (*ImageInfo, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("imgowner: invalid image reference %q: %w", imageRef, err)
	}
	// The CLI receives the name as the user wrote it (docker resolves short
	// names itself); ParseReference above guarantees it can't be read as a flag.
	for _, rt := range localRuntimes {
		bin, err := exec.LookPath(rt)
		if err != nil {
			continue
		}
		if exec.CommandContext(ctx, bin, "image", "inspect", "--format", "{{.Id}}", "--", imageRef).Run() != nil {
			continue
		}
		return exportLocal(ctx, bin, ref, imageRef, platform)
	}
	return nil, errNotLocal
}

// exportLocal saves imageRef from the runtime at bin into a private temporary
// directory and opens it as an image.
func exportLocal(ctx context.Context, bin string, ref name.Reference, imageRef, platform string) (*ImageInfo, error) {
	dir, err := os.MkdirTemp("", "imgowner-local-*") // 0700
	if err != nil {
		return nil, fmt.Errorf("imgowner: creating a temporary directory for %s: %w", imageRef, err)
	}
	archive := filepath.Join(dir, "image.tar")
	fail := func(err error) (*ImageInfo, error) {
		_ = os.RemoveAll(dir)
		return nil, err
	}

	// A multi-platform local image (containerd store) must be exported for
	// the platform being scanned; older CLIs lack --platform and hold only
	// one platform anyway, so retry without it.
	save := func(withPlatform bool) error {
		args := []string{"image", "save", "-o", archive}
		if withPlatform && platform != "" {
			args = append(args, "--platform", platform)
		}
		args = append(args, "--", imageRef)
		_, err := safeio.Output(exec.CommandContext(ctx, bin, args...), safeio.MaxToolOutput, "image save output")
		return err
	}
	if err := save(true); err != nil {
		if err2 := save(false); err2 != nil {
			return fail(fmt.Errorf("imgowner: exporting local image %s with %s: %v", imageRef, filepath.Base(bin), err2))
		}
	}

	var tag *name.Tag
	if t, ok := ref.(name.Tag); ok {
		tag = &t
	}
	img, err := tarball.ImageFromPath(archive, tag)
	if err != nil {
		return fail(fmt.Errorf("imgowner: reading exported image %s: %w", imageRef, err))
	}
	if err := checkPlatform(img, platform); err != nil {
		return fail(fmt.Errorf("imgowner: local image %s: %w", imageRef, err))
	}
	digest, err := img.Digest()
	if err != nil {
		return fail(fmt.Errorf("imgowner: digest of local image %s: %w", imageRef, err))
	}
	return &ImageInfo{
		Ref:     imageRef,
		Digest:  digest.String(),
		Image:   img,
		Archive: archive,
		Local:   true,
		cleanup: func() error { return os.RemoveAll(dir) },
	}, nil
}

// checkPlatform refuses a local image built for a different platform than
// the one being scanned, rather than reporting CVEs for the wrong binaries.
func checkPlatform(img v1.Image, platform string) error {
	if platform == "" {
		return nil
	}
	want, err := v1.ParsePlatform(platform)
	if err != nil {
		return fmt.Errorf("invalid platform %q: %w", platform, err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	got := cf.Platform()
	if got == nil || got.OS == "" {
		return nil // no platform recorded; nothing to compare
	}
	if got.OS != want.OS || got.Architecture != want.Architecture ||
		(want.Variant != "" && got.Variant != want.Variant) {
		return fmt.Errorf("built for %s, but scan.platform is %s", strings.TrimSuffix(got.OS+"/"+got.Architecture+"/"+got.Variant, "/"), platform)
	}
	return nil
}
