package dockerfile

import "testing"

// FuzzParseBytes feeds arbitrary bytes through the parser and base-ref
// resolution (FR-46). The Dockerfile is untrusted input: it comes from
// whatever repository the tool is pointed at. Neither step may panic or hang,
// whatever the content.
func FuzzParseBytes(f *testing.F) {
	seeds := []string{
		"FROM debian:12-slim\nRUN apt-get update\n",
		"ARG BASE_TAG=12-slim\nFROM debian:${BASE_TAG} AS base\nFROM base AS final\n",
		"FROM golang:1.23 AS deps\nFROM deps AS builder\nFROM builder AS final\n",
		"FROM a AS b\nFROM b AS a\n",
		"ARG X=$X\nFROM $X\n",
		"FROM debian\nRUN <<EOF\necho hi\nEOF\n",
		"FROM debian\nRUN apt-get install -y \\\n  curl=7.88.1-10 \\\n  openssl=3.0.11-1\n",
		"FROM\n",
		"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := ParseBytes(data)
		if err != nil {
			return
		}
		for i := range file.Stages {
			_ = file.ResolveBaseRef(&file.Stages[i])
		}
		if final := file.FinalStage(); final != nil {
			_ = file.ResolveBaseRef(final)
		}
	})
}
