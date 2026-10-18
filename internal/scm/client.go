package scm

import "context"

const prCommentMarker = "<!-- imgowner -->"

// PRClient can open or update a pull request and post (or update) a comment.
// Implementations are in github.go and ado.go.
type PRClient interface {
	// EnsureComment finds an existing imgowner comment on the PR identified by
	// prID and updates it, or creates a new one. The marker <!-- imgowner --> is
	// embedded in every comment to enable idempotent find-or-update (FR-24).
	EnsureComment(ctx context.Context, prID string, body string) error

	// OpenOrUpdatePR opens a new pull request or updates an existing one that
	// matches the given head branch. Returns the PR ID (number/URL).
	OpenOrUpdatePR(ctx context.Context, req PRRequest) (string, error)
}

// PRRequest holds the data needed to open or update a pull request.
type PRRequest struct {
	HeadBranch string
	BaseBranch string
	Title      string
	Body       string
}

// NewClient returns the right PRClient for the given Provider.
func NewClient(provider Provider) (PRClient, error) {
	switch provider {
	case ProviderGitHub:
		return newGitHubClient()
	case ProviderAzureDevOps:
		return newADOClient()
	default:
		return &noopClient{}, nil
	}
}

// noopClient is returned when no SCM is configured; all operations are no-ops.
type noopClient struct{}

func (n *noopClient) EnsureComment(_ context.Context, _ string, _ string) error { return nil }
func (n *noopClient) OpenOrUpdatePR(_ context.Context, _ PRRequest) (string, error) {
	return "", nil
}
