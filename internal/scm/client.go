package scm

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const prCommentMarker = "<!-- imgowner -->"

// PRClient can open or update a pull request and post (or update) a comment.
// Implementations are in github.go and ado.go.
type PRClient interface {
	// EnsureComment finds an existing imgowner comment on the PR identified by
	// prID and updates it, or creates a new one. The marker <!-- imgowner --> is
	// embedded in every comment to enable idempotent find-or-update (FR-26).
	EnsureComment(ctx context.Context, prID string, body string) error

	// OpenOrUpdatePR commits req.File to the imgowner branch and opens a pull
	// request for it, or updates the open one that carries the imgowner
	// marker (FR-21). It never touches a pull request without the marker.
	OpenOrUpdatePR(ctx context.Context, req PRRequest) (PRResult, error)
}

// PRRequest holds the data needed to open or update a pull request.
type PRRequest struct {
	// BranchPrefix is scm.branch_prefix. A prefix ending in "/" gets
	// "pin-updates" appended ("imgowner/" -> "imgowner/pin-updates");
	// otherwise it is the branch name ("fix/os-pins").
	BranchPrefix string
	// BaseBranch is the target; empty means the repository's default branch
	// (NFR-05), never an assumed "main".
	BaseBranch string
	Title      string
	Body       string
	// Labels is scm.labels. Labels that don't exist are skipped with a
	// warning and never created (FR-22).
	Labels []string
	// File is the change to commit: a repository-relative path with forward
	// slashes and the file's complete new content.
	File          FileChange
	CommitMessage string
}

// FileChange is one file's new content.
type FileChange struct {
	Path    string
	Content []byte
}

// PRResult describes what OpenOrUpdatePR did.
type PRResult struct {
	URL      string   // web URL of the pull request
	Created  bool     // false when an existing imgowner PR was updated
	Branch   string   // the branch the change was committed to
	Warnings []string // e.g. "Label 'security' not found — skipping."
}

// BranchName applies the branch-prefix rule documented on PRRequest.
func BranchName(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return "imgowner/pin-updates"
	}
	if strings.HasSuffix(prefix, "/") {
		return prefix + "pin-updates"
	}
	return prefix
}

var prIDRe = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)

// ValidPRID reports whether id is a pull request number. It is spliced into
// API paths, so anything else ("1/../../user") must be refused up front.
func ValidPRID(id string) error {
	if !prIDRe.MatchString(id) {
		return fmt.Errorf("invalid pull request id %q (expected a number)", id)
	}
	return nil
}

// httpClient bounds every SCM API call (NFR-01): a stalled API must fail the
// step rather than hang the CI job until its own timeout.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// NewClient returns the right PRClient for the given Provider.
func NewClient(provider Provider) (PRClient, error) {
	switch provider {
	case ProviderGitHub:
		return newGitHubClient()
	case ProviderAzureDevOps:
		return newADOClient()
	default:
		return nil, fmt.Errorf("scm: no SCM provider detected; set scm.provider in .imgowner.yaml or run inside GitHub Actions / Azure DevOps")
	}
}
