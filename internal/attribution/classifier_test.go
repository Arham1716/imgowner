package attribution

import (
	"testing"

	"github.com/Arham1716/imgowner/internal/image"
	"github.com/Arham1716/imgowner/internal/scan"
)

func TestClassify(t *testing.T) {
	layerMap := image.LayerMap{
		{Index: 0, DiffID: "sha256:base0"},
		{Index: 1, DiffID: "sha256:base1"},
		{Index: 2, DiffID: "sha256:added0", Command: "RUN apt-get install -y curl=7.88.1-10"},
		{Index: 3, DiffID: "sha256:app0", Command: "RUN pip install -r requirements.txt"},
	}
	baseLayerCount := 2

	results := []scan.TargetResult{
		{
			Class: "os-pkgs",
			Vulnerabilities: []scan.Vulnerability{
				{VulnerabilityID: "CVE-2024-0001", Severity: "HIGH",
					PkgName: "libc6", Layer: scan.Layer{DiffID: "sha256:base0"}},
				{VulnerabilityID: "CVE-2024-0002", Severity: "CRITICAL",
					PkgName: "curl", Layer: scan.Layer{DiffID: "sha256:added0"}},
			},
		},
		{
			Class: "lang-pkgs",
			Vulnerabilities: []scan.Vulnerability{
				{VulnerabilityID: "CVE-2024-0003", Severity: "MEDIUM",
					PkgName: "requests", Layer: scan.Layer{DiffID: "sha256:app0"}},
			},
		},
		{
			Class: "os-pkgs",
			Vulnerabilities: []scan.Vulnerability{
				{VulnerabilityID: "CVE-2024-0004", Severity: "LOW",
					PkgName: "unknown-pkg", Layer: scan.Layer{DiffID: ""}},
			},
		},
	}

	findings := Classify(results, layerMap, baseLayerCount)

	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}

	cases := []struct {
		cve   string
		owner Owner
	}{
		{"CVE-2024-0001", OwnerBase},
		{"CVE-2024-0002", OwnerAddedOS},
		{"CVE-2024-0003", OwnerApp},
		{"CVE-2024-0004", OwnerUnattributed},
	}

	for i, tc := range cases {
		f := findings[i]
		if f.CVE != tc.cve {
			t.Errorf("[%d] CVE: want %s got %s", i, tc.cve, f.CVE)
		}
		if f.Owner != tc.owner {
			t.Errorf("[%d] %s: want owner %s got %s", i, f.CVE, tc.owner, f.Owner)
		}
	}

	// Unattributed finding must have a reason string.
	if findings[3].UnattributedReason == "" {
		t.Error("unattributed finding missing reason string")
	}
}

func TestClassify_EmptyResults(t *testing.T) {
	findings := Classify(nil, image.LayerMap{}, 0)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
