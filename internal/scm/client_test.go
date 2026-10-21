package scm

import (
	"context"
	"testing"
)

func TestNewClient_UnknownProviderReturnsNoop(t *testing.T) {
	c, err := NewClient(ProviderUnknown)
	if err != nil {
		t.Fatalf("ProviderUnknown should yield a no-op client, not an error: %v", err)
	}
	// A no-op client must be safe to call without a configured SCM: callers
	// that run ci without PR integration must not crash on a nil client.
	if _, err := c.OpenOrUpdatePR(context.Background(), PRRequest{}); err != nil {
		t.Errorf("no-op OpenOrUpdatePR should not error, got: %v", err)
	}
	if err := c.EnsureComment(context.Background(), "1", "x"); err != nil {
		t.Errorf("no-op EnsureComment should not error, got: %v", err)
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
	_, err := NewClient(ProviderAzureDevOps)
	if err == nil {
		t.Error("NewClient(ProviderAzureDevOps) without AZURE_DEVOPS_TOKEN should error")
	}
}
