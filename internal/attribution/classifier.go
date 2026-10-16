// Package attribution classifies Trivy CVE findings by owner:
// base, added-os, app, or unattributed (FR-05 through FR-08).
package attribution

// Owner identifies who is responsible for a CVE finding.
type Owner string

const (
	OwnerBase        Owner = "base"
	OwnerAddedOS     Owner = "added-os"
	OwnerApp         Owner = "app"
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
	CVE              string
	Severity         string
	Package          string
	InstalledVersion string
	FixedVersion     string
	Class            string
	LayerDiffID      string
	LayerIndex       int
	Owner            Owner
	UnattributedReason string   // populated when Owner == OwnerUnattributed
	Instruction      *DockerfileRef
	Confidence       Confidence
}

// DockerfileRef points to a specific instruction in the Dockerfile.
type DockerfileRef struct {
	Line int
	Text string
}

// TODO M1: implement Classify(findings []scan.Vulnerability, layerMap LayerMap, baseLayers int) []Finding
