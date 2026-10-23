package attribution

import (
	"bytes"
	"encoding/json"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/Arham1716/imgowner/internal/dockerfile"
	"github.com/Arham1716/imgowner/internal/image"
	"github.com/Arham1716/imgowner/internal/scan"
)

// FuzzAttribute drives the whole attribution step from its three untrusted
// inputs (FR-46): the image config (from a registry), the Trivy report (from
// scanning that image) and the Dockerfile. Any of them can be malformed or
// hostile; none may make attribution panic, and every finding must come out
// with a known owner.
func FuzzAttribute(f *testing.F) {
	cfg := `{"rootfs":{"type":"layers","diff_ids":["sha256:aaaa","sha256:bbbb"]},` +
		`"history":[{"created_by":"/bin/sh -c #(nop) ADD file:x in /"},` +
		`{"created_by":"WORKDIR /app","empty_layer":true},` +
		`{"created_by":"RUN /bin/sh -c apt-get install -y curl # buildkit"}]}`
	report := `{"Results":[{"Target":"debian","Class":"os-pkgs","Vulnerabilities":[` +
		`{"VulnerabilityID":"CVE-1","PkgName":"curl","Layer":{"DiffID":"sha256:bbbb"}},` +
		`{"VulnerabilityID":"CVE-2","PkgName":"libc","Layer":{"DiffID":"sha256:aaaa"}},` +
		`{"VulnerabilityID":"CVE-3","PkgName":"x","Layer":{"DiffID":"sha256:zzzz"}}]}]}`
	df := "FROM debian:12\nWORKDIR /app\nRUN apt-get install -y curl\n"
	f.Add([]byte(cfg), []byte(report), []byte(df), 1, true)
	f.Add([]byte(`{"rootfs":{"diff_ids":[]},"history":[{}]}`), []byte(`{}`), []byte("FROM scratch\n"), 0, false)
	f.Add([]byte(`{}`), []byte(`{"Results":null}`), []byte(""), -5, true)

	known := map[Owner]bool{OwnerBase: true, OwnerAddedOS: true, OwnerApp: true, OwnerUnattributed: true}

	f.Fuzz(func(t *testing.T, cfgJSON, reportJSON, dfBytes []byte, baseLayers int, confident bool) {
		cf, err := v1.ParseConfigFile(bytes.NewReader(cfgJSON))
		if err != nil {
			return
		}
		layerMap, err := image.BuildLayerMap(cf)
		if err != nil {
			return
		}
		var res scan.Result
		if err := json.Unmarshal(reportJSON, &res); err != nil {
			return
		}
		parsed, err := dockerfile.ParseBytes(dfBytes)
		if err != nil {
			parsed = nil
		}
		base := &image.BaseResolution{LayerCount: baseLayers, Confident: confident}
		if !confident {
			base.Reason = "fuzz"
		}

		findings := Classify(res.Results, layerMap, base)
		findings = MapToDockerfileLines(findings, layerMap, parsed)
		for _, fd := range findings {
			if !known[fd.Owner] {
				t.Fatalf("finding %s has unknown owner %q", fd.CVE, fd.Owner)
			}
		}
	})
}
