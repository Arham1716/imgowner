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
	CVE                string
	Severity           string
	Package            string
	InstalledVersion   string
	FixedVersion       string
	Class              string
	LayerDiffID        string
	LayerIndex         int
	Owner              Owner
	UnattributedReason string
	Instruction        *DockerfileRef
	Confidence         Confidence
}

// DockerfileRef points to a specific instruction in the Dockerfile.
type DockerfileRef struct {
	Line int
	Text string
}

// Classify attributes every Trivy finding to an owner using the layer map and
// base layer count (FR-05, FR-07, FR-08).
func Classify(
	results []scan.TargetResult,
	layerMap image.LayerMap,
	baseLayerCount int,
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
			case entry.Index < baseLayerCount:
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

func unattributedReason(diffID string) string {
	if diffID == "" {
		return "no DiffID in Trivy output — image may be squashed"
	}
	return "DiffID not found in image layer map: " + diffID
}
