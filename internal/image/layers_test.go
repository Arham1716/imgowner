package image

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestBuildLayerMap(t *testing.T) {
	cf := &v1.ConfigFile{
		RootFS: v1.RootFS{
			DiffIDs: []v1.Hash{
				{Algorithm: "sha256", Hex: "aaaa"},
				{Algorithm: "sha256", Hex: "bbbb"},
				{Algorithm: "sha256", Hex: "cccc"},
			},
		},
		History: []v1.History{
			{CreatedBy: "FROM debian:12", EmptyLayer: false},
			{CreatedBy: "ENV PATH=/usr/local/bin", EmptyLayer: true}, // empty — no DiffID consumed
			{CreatedBy: "RUN apt-get update", EmptyLayer: false},
			{CreatedBy: "RUN pip install flask", EmptyLayer: false},
		},
	}

	lm, err := BuildLayerMap(cf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(lm) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(lm))
	}

	// Non-empty entries must have DiffIDs assigned in order.
	if lm[0].DiffID != "sha256:aaaa" {
		t.Errorf("layer 0 DiffID: want sha256:aaaa got %s", lm[0].DiffID)
	}
	if !lm[1].IsEmpty {
		t.Error("layer 1 should be empty (ENV instruction)")
	}
	if lm[1].DiffID != "" {
		t.Errorf("empty layer should have no DiffID, got %s", lm[1].DiffID)
	}
	if lm[2].DiffID != "sha256:bbbb" {
		t.Errorf("layer 2 DiffID: want sha256:bbbb got %s", lm[2].DiffID)
	}
	if lm[3].DiffID != "sha256:cccc" {
		t.Errorf("layer 3 DiffID: want sha256:cccc got %s", lm[3].DiffID)
	}
}

func TestBaseLayerCount(t *testing.T) {
	hash := func(h string) v1.Hash { return v1.Hash{Algorithm: "sha256", Hex: h} }

	finalCF := &v1.ConfigFile{RootFS: v1.RootFS{DiffIDs: []v1.Hash{
		hash("a"), hash("b"), hash("c"), hash("d"),
	}}}
	baseCF := &v1.ConfigFile{RootFS: v1.RootFS{DiffIDs: []v1.Hash{
		hash("a"), hash("b"),
	}}}

	count, err := BaseLayerCount(finalCF, baseCF)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected base layer count 2, got %d", count)
	}
}

func TestBaseLayerCount_Mismatch(t *testing.T) {
	hash := func(h string) v1.Hash { return v1.Hash{Algorithm: "sha256", Hex: h} }

	finalCF := &v1.ConfigFile{RootFS: v1.RootFS{DiffIDs: []v1.Hash{hash("a"), hash("b")}}}
	baseCF := &v1.ConfigFile{RootFS: v1.RootFS{DiffIDs: []v1.Hash{hash("a"), hash("x")}}}

	_, err := BaseLayerCount(finalCF, baseCF)
	if err == nil {
		t.Error("expected error for DiffID mismatch, got nil")
	}
}
