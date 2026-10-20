package image

import (
	"context"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestPinToDigest(t *testing.T) {
	cases := []struct {
		name, ref, digest, want string
	}{
		{"tagged ref", "python:3.12-slim", "sha256:abc", "python:3.12-slim@sha256:abc"},
		{"untagged ref", "python", "sha256:abc", "python@sha256:abc"},
		{"replaces existing digest", "python@sha256:old", "sha256:new", "python@sha256:new"},
		{"registry host preserved", "ghcr.io/org/app:v1", "sha256:abc", "ghcr.io/org/app:v1@sha256:abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pinToDigest(tc.ref, tc.digest); got != tc.want {
				t.Errorf("pinToDigest(%q, %q) = %q, want %q", tc.ref, tc.digest, got, tc.want)
			}
		})
	}
}

func TestResolveBase_EmptyRef(t *testing.T) {
	cf := &v1.ConfigFile{}
	got := ResolveBase(context.Background(), cf, "", "", "linux/amd64")

	if got.Confident {
		t.Error("empty base ref must not be reported as confident")
	}
	if got.Reason == "" {
		t.Error("empty base ref must carry a reason")
	}
}

// Without a pinned digest the mismatch message must point the user at
// --base-digest, since a moved tag is by far the most common cause.
func TestBaseMismatchReason_SuggestsDigestPin(t *testing.T) {
	err := errTest("diff_id mismatch at layer 0")

	unpinned := baseMismatchReason(err, "")
	if !strings.Contains(unpinned, "--base-digest") {
		t.Errorf("unpinned mismatch should suggest --base-digest, got: %s", unpinned)
	}

	// With a digest already pinned, suggesting the same flag again is useless.
	pinned := baseMismatchReason(err, "sha256:abc")
	if strings.Contains(pinned, "re-run with --base-digest") {
		t.Errorf("pinned mismatch must not re-suggest --base-digest, got: %s", pinned)
	}
	if !strings.Contains(pinned, "squashed") {
		t.Errorf("pinned mismatch should explain other causes, got: %s", pinned)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
