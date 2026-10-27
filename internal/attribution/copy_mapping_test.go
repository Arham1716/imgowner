package attribution

import (
	"testing"

	"github.com/Arham1716/imgowner/internal/dockerfile"
	"github.com/Arham1716/imgowner/internal/image"
)

// History text below is exactly what BuildKit recorded for this Dockerfile in
// a real build (docker history --no-trunc). The acceptance run found every
// finding in a COPY/ADD layer (node_modules, jars, Go binaries) with no
// Dockerfile line, because only RUN lines were candidates.
const multiStage = `FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -o /hello .
FROM alpine:3.20 AS base
RUN apk add --no-cache curl
FROM base
WORKDIR /app
COPY --from=build /hello /usr/local/bin/hello
ADD https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar /app/lib/
COPY --chown=1000:1000 main.go /app/
CMD ["hello"]
`

func TestMapToDockerfileLines_CopyAndAddLayers(t *testing.T) {
	df, err := dockerfile.ParseBytes([]byte(multiStage))
	if err != nil {
		t.Fatal(err)
	}
	lm := image.LayerMap{
		{DiffID: "sha256:base", Command: "ADD alpine-minirootfs-3.20.10-x86_64.tar.gz / # buildkit"},
		{DiffID: "sha256:curl", Command: "RUN /bin/sh -c apk add --no-cache curl # buildkit"},
		{DiffID: "sha256:hello", Command: "COPY /hello /usr/local/bin/hello # buildkit"},
		{DiffID: "sha256:jar", Command: "ADD https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar /app/lib/ # buildkit"},
		{DiffID: "sha256:main", Command: "COPY --chown=1000:1000 main.go /app/ # buildkit"},
	}
	findings := []Finding{
		{CVE: "a", LayerDiffID: "sha256:hello"},
		{CVE: "b", LayerDiffID: "sha256:jar"},
		{CVE: "c", LayerDiffID: "sha256:main"},
		{CVE: "d", LayerDiffID: "sha256:curl"},
		{CVE: "e", LayerDiffID: "sha256:base"},
	}
	got := MapToDockerfileLines(findings, lm, df)
	want := map[string]int{"a": 9, "b": 10, "c": 11, "d": 6, "e": 0}
	for _, f := range got {
		line := 0
		if f.Instruction != nil {
			line = f.Instruction.Line
		}
		if line != want[f.CVE] {
			t.Errorf("%s: line %d, want %d (%+v)", f.CVE, line, want[f.CVE], f.Instruction)
		}
	}
}

// The builder stage's "COPY go.mod main.go ./" and its RUN are not layers of
// the final image and must never be cited.
func TestMapToDockerfileLines_IgnoresBuilderStages(t *testing.T) {
	df, err := dockerfile.ParseBytes([]byte(multiStage))
	if err != nil {
		t.Fatal(err)
	}
	lm := image.LayerMap{{DiffID: "sha256:x", Command: "RUN /bin/sh -c CGO_ENABLED=0 go build -o /hello . # buildkit"}}
	got := MapToDockerfileLines([]Finding{{CVE: "x", LayerDiffID: "sha256:x"}}, lm, df)
	if got[0].Instruction != nil {
		t.Errorf("cited a builder-stage line: %+v", got[0].Instruction)
	}
}
