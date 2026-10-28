package scm

import (
	"testing"
)

// With no provider there is nothing to talk to; v0.5.0 returned a no-op
// client here, so `pins update --open-pr` printed "PR: " and exited 0 and ci
// silently posted no comment. It must be an error the caller reports.
func TestNewClient_UnknownProviderIsAnError(t *testing.T) {
	if _, err := NewClient(ProviderUnknown); err == nil {
		t.Fatal("NewClient(ProviderUnknown) returned a client")
	}
}

func TestNewClient_GitHubRequiresEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	_, err := NewClient(ProviderGitHub)
	if err == nil {
		t.Error("NewClient(ProviderGitHub) without GITHUB_TOKEN/GITHUB_REPOSITORY should error")
	}
}

func TestNewClient_AzureDevOpsRequiresEnv(t *testing.T) {
	t.Setenv("AZURE_DEVOPS_TOKEN", "")
	t.Setenv("SYSTEM_ACCESSTOKEN", "")
	_, err := NewClient(ProviderAzureDevOps)
	if err == nil {
		t.Error("NewClient(ProviderAzureDevOps) without AZURE_DEVOPS_TOKEN should error")
	}
}
