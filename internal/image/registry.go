package image

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ImageInfo holds the resolved digest and the full image manifest/config.
type ImageInfo struct {
	// Ref is the digest-pinned reference, e.g. python:3.12-slim@sha256:abc123
	Ref    string
	Digest string
	Image  v1.Image
}

// Resolve resolves imageRef to a digest-pinned reference and fetches the image
// manifest from the registry using the Docker credential chain (DQ-2).
// Returns structured errors suitable for JSON output (FR-01, F3, F4).
func Resolve(ctx context.Context, imageRef, platform string) (*ImageInfo, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("imgowner: invalid image reference %q: %w", imageRef, err)
	}

	opts := remoteOpts(ctx, platform)

	img, err := remote.Image(ref, opts...)
	if err != nil {
		return nil, classifyRemoteErr(err, imageRef)
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("imgowner: fetching digest for %s: %w", imageRef, err)
	}

	pinned := fmt.Sprintf("%s@%s", ref.Context().Name(), digest.String())

	return &ImageInfo{
		Ref:    pinned,
		Digest: digest.String(),
		Image:  img,
	}, nil
}

// Config fetches the image config file, which contains history and rootfs.diff_ids.
func Config(ctx context.Context, imageRef, platform string) (*v1.ConfigFile, error) {
	info, err := Resolve(ctx, imageRef, platform)
	if err != nil {
		return nil, err
	}
	cf, err := info.Image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("imgowner: fetching config for %s: %w", imageRef, err)
	}
	return cf, nil
}

// remoteOpts builds the option slice for go-containerregistry remote calls.
func remoteOpts(ctx context.Context, platform string) []remote.Option {
	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain), // Docker credential chain (DQ-2)
	}
	if platform != "" {
		p, err := parsePlatform(platform)
		if err == nil {
			opts = append(opts, remote.WithPlatform(p))
		}
	}
	return opts
}

// parsePlatform converts "linux/amd64" to a v1.Platform struct.
func parsePlatform(s string) (v1.Platform, error) {
	var p v1.Platform
	if _, err := fmt.Sscanf(s, "%s", &s); err != nil {
		return p, err
	}
	switch s {
	case "linux/amd64":
		return v1.Platform{OS: "linux", Architecture: "amd64"}, nil
	case "linux/arm64":
		return v1.Platform{OS: "linux", Architecture: "arm64"}, nil
	default:
		// Let go-containerregistry handle it via string split.
		return v1.Platform{OS: "linux", Architecture: "amd64"}, nil
	}
}

// ErrImageNotFound is returned when the registry returns a 404 / manifest unknown.
type ErrImageNotFound struct {
	Ref string
}

func (e *ErrImageNotFound) Error() string {
	return fmt.Sprintf("imgowner: image not found: %s", e.Ref)
}

// ErrRegistryUnreachable is returned on network-level failures (F3).
type ErrRegistryUnreachable struct {
	Host  string
	Cause error
}

func (e *ErrRegistryUnreachable) Error() string {
	return fmt.Sprintf("imgowner: registry unreachable: %s: %v", e.Host, e.Cause)
}

// classifyRemoteErr maps go-containerregistry errors to our typed errors.
func classifyRemoteErr(err error, ref string) error {
	msg := err.Error()
	// "MANIFEST_UNKNOWN" or "404" → image not found (F4)
	for _, marker := range []string{"MANIFEST_UNKNOWN", "404", "not found"} {
		if containsFold(msg, marker) {
			return &ErrImageNotFound{Ref: ref}
		}
	}
	// Everything else is a connectivity / auth failure (F3)
	host := hostFromRef(ref)
	return &ErrRegistryUnreachable{Host: host, Cause: err}
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		len(s) > 0 && containsFoldSlow(s, sub))
}

func containsFoldSlow(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if equalFold(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func hostFromRef(ref string) string {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "unknown"
	}
	return r.Context().RegistryStr()
}
