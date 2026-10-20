package attribution

import (
	"strings"

	"github.com/Arham1716/imgowner/internal/image"
	"github.com/Arham1716/imgowner/internal/scan"
)

// Owner identifies who is responsible for a CVE finding.
type Owner string

const (
	OwnerBase         Owner = "base"
	OwnerAddedOS      Owner = "added-os"
	OwnerApp          Owner = "app"
	OwnerUnattributed Owner = "unattributed"
)

// Confidence describes how confidently a finding was mapped to a Dockerfile line.
type Confidence string

const (
	ConfidenceExact Confidence = "exact"
	ConfidenceFuzzy Confidence = "fuzzy"
	ConfidenceNone  Confidence = "none"
)

// Finding is a single attributed CVE finding.
type Finding struct {
	CVE                string         `json:"cve"`
	Severity           string         `json:"severity"`
	Package            string         `json:"package"`
	InstalledVersion   string         `json:"installed_version"`
	FixedVersion       string         `json:"fixed_version"`
	Class              string         `json:"class"`
	LayerDiffID        string         `json:"layer_diff_id,omitempty"`
	LayerIndex         int            `json:"layer_index"`
	Owner              Owner          `json:"owner"`
	UnattributedReason string         `json:"unattributed_reason,omitempty"`
	Instruction        *DockerfileRef `json:"instruction,omitempty"`
	Confidence         Confidence     `json:"confidence"`
}

// DockerfileRef points to a specific instruction in the Dockerfile.
type DockerfileRef struct {
	Line int    `json:"line"`
	Text string `json:"text"`
}

// Classify attributes every Trivy finding to an owner using the layer map and
// the resolved base image boundary (FR-05, FR-07, FR-08).
//
// When base.Confident is false the layer boundary is unknown, so every finding
// is reported as unattributed with the reason. Guessing an owner here would
// silently blame the wrong team for vulnerabilities they do not control.
func Classify(
	results []scan.TargetResult,
	layerMap image.LayerMap,
	base *image.BaseResolution,
) []Finding {
	var findings []Finding

	for _, target := range results {
		for _, v := range target.Vulnerabilities {
			f := Finding{
				CVE:              v.VulnerabilityID,
				Severity:         v.Severity,
				Package:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Class:            target.Class,
				LayerDiffID:      v.Layer.DiffID,
				LayerIndex:       -1,
				Confidence:       ConfidenceNone,
			}

			entry := layerMap.FindByDiffID(v.Layer.DiffID)
			if entry == nil || v.Layer.DiffID == "" {
				f.Owner = OwnerUnattributed
				f.UnattributedReason = unattributedReason(v.Layer.DiffID)
				findings = append(findings, f)
				continue
			}

			f.LayerIndex = entry.Index

			switch {
			case base == nil || !base.Confident:
				// The base/added-os split is derived entirely from layer position,
				// so an unverified boundary makes every owner a guess (FR-06).
				f.Owner = OwnerUnattributed
				f.UnattributedReason = "base image boundary unverified: " + baseReason(base)

			case entry.Index < base.LayerCount:
				// Layer is part of the base image (FR-05).
				f.Owner = OwnerBase

			case isLangPkgs(target.Class):
				// Language packages after the base → app (FR-05, FR-07).
				f.Owner = OwnerApp

			case isOSPkgs(target.Class):
				// OS packages after the base → added-os (FR-05, FR-07).
				f.Owner = OwnerAddedOS

			default:
				f.Owner = OwnerUnattributed
				f.UnattributedReason = "unknown class: " + target.Class
			}

			findings = append(findings, f)
		}
	}

	return findings
}

func isOSPkgs(class string) bool  { return strings.EqualFold(class, "os-pkgs") }
func isLangPkgs(class string) bool { return strings.EqualFold(class, "lang-pkgs") }

func baseReason(base *image.BaseResolution) string {
	if base == nil {
		return "base image was not resolved"
	}
	if base.Reason == "" {
		return "no reason recorded"
	}
	return base.Reason
}

func unattributedReason(diffID string) string {
	if diffID == "" {
		return "no DiffID in Trivy output — image may be squashed"
	}
	return "DiffID not found in image layer map: " + diffID
}
