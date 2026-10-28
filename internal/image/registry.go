package image

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// DefaultResolveTimeout bounds a registry lookup (manifest and config — small
// JSON documents, not image layers) when the caller set no deadline of its
// own. Before this, a registry that accepted the connection and never
// answered — or never answered at all — could hang the whole command forever,
// with no way out short of Ctrl+C. The acceptance suite's own expectation
// (test/../edge.sh) is that this resolves within about two minutes; this
// stays comfortably under that.
//
// ResolveAny's local-image fallback (`docker image save` of a locally built
// image, batch 2b) runs under this same bound, which is why it is more
// generous than a registry round-trip alone would need: `docker save` only
// copies already-compressed layer blobs to a tarball, no recompression, so
// even a multi-GB image finishes in well under this on any normal disk.
const DefaultResolveTimeout = 90 * time.Second

// WithResolveTimeout applies DefaultResolveTimeout unless ctx already has a
// deadline, mirroring the rule pins.LookupVersions and scan.withVersionTimeout
// use for their own timeouts.
func WithResolveTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, DefaultResolveTimeout)
}

// ImageInfo holds the resolved digest and the full image manifest/config.
type ImageInfo struct {
	// Ref is the digest-pinned reference, e.g. python:3.12-slim@sha256:abc123,
	// or for a local image the reference as given.
	Ref    string
	Digest string
	Image  v1.Image
	// Archive is the exported image tarball for a local image (Local true);
	// scanners must read it instead of pulling Ref. Empty for registry images.
	Archive string
	Local   bool

	cleanup func() error
}

// Close removes a local image's temporary archive. It is a no-op for
// registry images and safe to call more than once.
func (i *ImageInfo) Close() error {
	if i == nil || i.cleanup == nil {
		return nil
	}
	err := i.cleanup()
	i.cleanup = nil
	return err
}

// Resolve resolves imageRef to a digest-pinned reference and fetches the image
// manifest from the registry using the Docker credential chain (DQ-2).
// Returns structured errors suitable for JSON output (FR-01, F3, F4).
func Resolve(ctx context.Context, imageRef, platform string) (*ImageInfo, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("imgowner: invalid image reference %q: %w", imageRef, err)
	}

	opts, err := remoteOpts(ctx, platform)
	if err != nil {
		return nil, err
	}

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

// remoteOpts builds the option slice for go-containerregistry remote calls.
// An unparseable platform is an error rather than a silent fallback: scanning
// a different architecture than the caller asked for would report CVEs for
// binaries that are not in their image.
func remoteOpts(ctx context.Context, platform string) ([]remote.Option, error) {
	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain), // Docker credential chain (DQ-2)
	}
	if platform == "" {
		return opts, nil
	}
	p, err := v1.ParsePlatform(platform)
	if err != nil {
		return nil, fmt.Errorf(
			"imgowner: invalid platform %q (expected os/arch, e.g. linux/amd64): %w", platform, err)
	}
	return append(opts, remote.WithPlatform(*p)), nil
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

// ErrRegistryAuth is returned when the registry rejects the credentials.
type ErrRegistryAuth struct {
	Host string
	Ref  string
}

func (e *ErrRegistryAuth) Error() string {
	return fmt.Sprintf(
		"imgowner: not authorised for %s — run `docker login %s` or set registry credentials",
		e.Ref, e.Host)
}

// ErrRateLimited is returned when the registry throttles the request.
// Docker Hub caps anonymous pulls per IP, which CI runners hit routinely once
// base image recommendation starts scanning candidate tags.
type ErrRateLimited struct {
	Host string
}

func (e *ErrRateLimited) Error() string {
	return fmt.Sprintf(
		"imgowner: %s rate-limited this request — authenticate with `docker login %s` "+
			"to raise the limit, or lower scan.base_candidates", e.Host, e.Host)
}

// classifyRemoteErr maps registry failures to typed errors. HTTP status codes
// are read from the transport error where available; string matching is only a
// fallback for transports that do not surface one.
func classifyRemoteErr(err error, ref string) error {
	host := hostFromRef(ref)

	var terr *transport.Error
	if errors.As(err, &terr) {
		switch terr.StatusCode {
		case 404:
			return &ErrImageNotFound{Ref: ref}
		case 401, 403:
			return &ErrRegistryAuth{Host: host, Ref: ref}
		case 429:
			return &ErrRateLimited{Host: host}
		}
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "manifest_unknown"), strings.Contains(msg, "not found"):
		return &ErrImageNotFound{Ref: ref}
	case strings.Contains(msg, "toomanyrequests"), strings.Contains(msg, "too many requests"):
		return &ErrRateLimited{Host: host}
	case strings.Contains(msg, "unauthorized"), strings.Contains(msg, "denied"):
		return &ErrRegistryAuth{Host: host, Ref: ref}
	}

	return &ErrRegistryUnreachable{Host: host, Cause: err}
}

func hostFromRef(ref string) string {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "unknown"
	}
	return r.Context().RegistryStr()
}
