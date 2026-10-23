package scm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Arham1716/imgowner/internal/safeio"
)

// gitHubClient implements PRClient for GitHub via the REST API.
// Auth: GITHUB_TOKEN env var (standard GitHub Actions token).
type gitHubClient struct {
	token  string
	repo   string // "owner/repo"
	apiURL string // defaults to https://api.github.com
}

func newGitHubClient() (*gitHubClient, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("scm: GITHUB_TOKEN not set")
	}
	repo := os.Getenv("GITHUB_REPOSITORY") // set by GitHub Actions
	if repo == "" {
		return nil, fmt.Errorf("scm: GITHUB_REPOSITORY not set (owner/repo)")
	}
	apiURL := os.Getenv("GITHUB_API_URL")
	if apiURL == "" {
		apiURL = "https://api.github.com"
	}
	return &gitHubClient{token: token, repo: repo, apiURL: apiURL}, nil
}

func (g *gitHubClient) OpenOrUpdatePR(ctx context.Context, req PRRequest) (string, error) {
	// Search for an existing open PR from head → base.
	url := fmt.Sprintf("%s/repos/%s/pulls?head=%s&base=%s&state=open",
		g.apiURL, g.repo, req.HeadBranch, req.BaseBranch)
	existing, err := g.ghGET(ctx, url)
	if err != nil {
		return "", fmt.Errorf("scm(gh): list PRs: %w", err)
	}
	var prs []struct {
		Number int    `json:"number"`
		URL    string `json:"html_url"`
	}
	if err := json.Unmarshal(existing, &prs); err != nil {
		return "", fmt.Errorf("scm(gh): parse PR list: %w", err)
	}

	body := map[string]string{
		"title": req.Title,
		"body":  req.Body + "\n\n" + prCommentMarker,
		"head":  req.HeadBranch,
		"base":  req.BaseBranch,
	}

	if len(prs) > 0 {
		// Update existing PR.
		patchURL := fmt.Sprintf("%s/repos/%s/pulls/%d", g.apiURL, g.repo, prs[0].Number)
		if _, err := g.ghPATCH(ctx, patchURL, body); err != nil {
			return "", fmt.Errorf("scm(gh): update PR: %w", err)
		}
		return prs[0].URL, nil
	}

	// Open a new PR.
	createURL := fmt.Sprintf("%s/repos/%s/pulls", g.apiURL, g.repo)
	resp, err := g.ghPOST(ctx, createURL, body)
	if err != nil {
		return "", fmt.Errorf("scm(gh): create PR: %w", err)
	}
	var created struct {
		URL string `json:"html_url"`
	}
	if err := json.Unmarshal(resp, &created); err != nil {
		return "", fmt.Errorf("scm(gh): parse create response: %w", err)
	}
	return created.URL, nil
}

func (g *gitHubClient) EnsureComment(ctx context.Context, prID string, body string) error {
	// List existing issue comments for the PR.
	listURL := fmt.Sprintf("%s/repos/%s/issues/%s/comments", g.apiURL, g.repo, prID)
	data, err := g.ghGET(ctx, listURL)
	if err != nil {
		return fmt.Errorf("scm(gh): list comments: %w", err)
	}
	var comments []struct {
		ID   int    `json:"id"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal(data, &comments); err != nil {
		return fmt.Errorf("scm(gh): parse comments: %w", err)
	}

	fullBody := prCommentMarker + "\n\n" + body

	// Find an existing imgowner comment.
	for _, c := range comments {
		if strings.Contains(c.Body, prCommentMarker) {
			patchURL := fmt.Sprintf("%s/repos/%s/issues/comments/%d", g.apiURL, g.repo, c.ID)
			_, err := g.ghPATCH(ctx, patchURL, map[string]string{"body": fullBody})
			return err
		}
	}

	// No existing comment — create one.
	_, err = g.ghPOST(ctx, listURL, map[string]string{"body": fullBody})
	return err
}

func (g *gitHubClient) ghGET(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return g.do(req)
}

func (g *gitHubClient) ghPOST(ctx context.Context, url string, payload any) ([]byte, error) {
	return g.ghSend(ctx, http.MethodPost, url, payload)
}

func (g *gitHubClient) ghPATCH(ctx context.Context, url string, payload any) ([]byte, error) {
	return g.ghSend(ctx, http.MethodPatch, url, payload)
}

func (g *gitHubClient) ghSend(ctx context.Context, method, url string, payload any) ([]byte, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return g.do(req)
}

func (g *gitHubClient) do(req *http.Request) ([]byte, error) {
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := safeio.ReadAll(resp.Body, safeio.MaxHTTPBody, "github API response")
	if err != nil {
		return nil, fmt.Errorf("reading github API response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("github API %s %s → %d: %s", req.Method, req.URL, resp.StatusCode, body)
	}
	return body, nil
}
