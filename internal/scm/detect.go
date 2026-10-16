package scm

import (
	"fmt"
	"os"
)

// Provider identifies the SCM system.
type Provider int

const (
	ProviderUnknown Provider = iota
	ProviderGitHub
	ProviderAzureDevOps
)

// Detect returns the active SCM provider by inspecting well-known environment
// variables (DQ-3). Falls back to the explicit value from config if env is absent.
func Detect(configProvider string) (Provider, error) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return ProviderGitHub, nil
	}
	if os.Getenv("TF_BUILD") == "true" {
		return ProviderAzureDevOps, nil
	}

	switch configProvider {
	case "github":
		return ProviderGitHub, nil
	case "azure-devops":
		return ProviderAzureDevOps, nil
	case "auto", "":
		return ProviderUnknown, fmt.Errorf(
			`imgowner: scm provider undetectable — ` +
				`set scm.provider in .imgowner.yaml or run inside GitHub Actions / Azure DevOps`,
		)
	default:
		return ProviderUnknown, fmt.Errorf("imgowner: unknown scm.provider value %q", configProvider)
	}
}
