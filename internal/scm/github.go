package scm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
	return &gitHubClient{token: token, repo: repo, apiURL: strings.TrimRight(apiURL, "/")}, nil
}

// errNotFound marks a 404 from the API.
var errNotFound = errors.New("not found")

type ghPull struct {
	Number int    `json:"number"`
	URL    string `json:"html_url"`
	Body   string `json:"body"`
	Head   struct {
		Ref  string `json:"ref"`
		Repo *struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
}

func (g *gitHubClient) OpenOrUpdatePR(ctx context.Context, req PRRequest) (PRResult, error) {
	var res PRResult
	base := req.BaseBranch
	if base == "" {
		var repo struct {
			DefaultBranch string `json:"default_branch"`
		}
		if err := g.getJSON(ctx, g.repoURL(""), &repo); err != nil {
			return res, fmt.Errorf("scm(gh): reading the default branch: %w", err)
		}
		base = repo.DefaultBranch
	}

	// FR-21: the existing PR is the open one carrying the marker, opened from
	// this repository (never a fork, never an unrelated PR). The old lookup
	// used ?head=<branch>, which GitHub ignores without an "owner:" prefix,
	// so it matched -- and rewrote -- whatever PR happened to be open first.
	existing, err := g.findMarkedPR(ctx, base)
	if err != nil {
		return res, err
	}
	branch := BranchName(req.BranchPrefix)
	if existing != nil {
		branch = existing.Head.Ref
	}
	res.Branch = branch

	if err := g.ensureBranch(ctx, branch, base); err != nil {
		return res, err
	}
	if err := g.commitFile(ctx, branch, req.File, req.CommitMessage); err != nil {
		return res, err
	}

	body := req.Body + "\n\n" + prCommentMarker
	var pr ghPull
	if existing != nil {
		if err := g.sendJSON(ctx, http.MethodPatch, g.repoURL(fmt.Sprintf("/pulls/%d", existing.Number)),
			map[string]string{"title": req.Title, "body": body}, &pr); err != nil {
			return res, fmt.Errorf("scm(gh): update PR #%d: %w", existing.Number, err)
		}
	} else {
		if err := g.sendJSON(ctx, http.MethodPost, g.repoURL("/pulls"),
			map[string]string{"title": req.Title, "body": body, "head": branch, "base": base}, &pr); err != nil {
			return res, fmt.Errorf("scm(gh): create PR: %w", err)
		}
		res.Created = true
	}
	res.URL = pr.URL

	res.Warnings = g.applyLabels(ctx, pr.Number, req.Labels)
	return res, nil
}

func (g *gitHubClient) findMarkedPR(ctx context.Context, base string) (*ghPull, error) {
	pages, err := g.getAll(ctx, g.repoURL("/pulls?state=open&base="+url.QueryEscape(base)))
	if err != nil {
		return nil, fmt.Errorf("scm(gh): list PRs: %w", err)
	}
	for _, raw := range pages {
		var p ghPull
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("scm(gh): parse PR list: %w", err)
		}
		if strings.Contains(p.Body, prCommentMarker) && p.Head.Repo != nil && strings.EqualFold(p.Head.Repo.FullName, g.repo) {
			return &p, nil
		}
	}
	return nil, nil
}

// ensureBranch creates branch from base's head if it doesn't exist yet. An
// existing branch is reused as is: commits go on top of it, never a reset.
func (g *gitHubClient) ensureBranch(ctx context.Context, branch, base string) error {
	var ref struct{}
	err := g.getJSON(ctx, g.repoURL("/git/ref/heads/"+escapeRef(branch)), &ref)
	if err == nil {
		return nil
	}
	if !errors.Is(err, errNotFound) {
		return fmt.Errorf("scm(gh): reading branch %s: %w", branch, err)
	}
	var baseRef struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := g.getJSON(ctx, g.repoURL("/git/ref/heads/"+escapeRef(base)), &baseRef); err != nil {
		return fmt.Errorf("scm(gh): reading base branch %s: %w", base, err)
	}
	if err := g.sendJSON(ctx, http.MethodPost, g.repoURL("/git/refs"),
		map[string]string{"ref": "refs/heads/" + branch, "sha": baseRef.Object.SHA}, nil); err != nil {
		return fmt.Errorf("scm(gh): creating branch %s: %w", branch, err)
	}
	return nil
}

// commitFile writes f to branch through the contents API (one commit),
// unless the branch already holds exactly that content.
func (g *gitHubClient) commitFile(ctx context.Context, branch string, f FileChange, message string) error {
	if f.Path == "" {
		return fmt.Errorf("scm(gh): no file to commit")
	}
	fileURL := g.repoURL("/contents/" + escapePath(f.Path))
	var current struct {
		SHA     string `json:"sha"`
		Content string `json:"content"`
	}
	err := g.getJSON(ctx, fileURL+"?ref="+url.QueryEscape(branch), &current)
	switch {
	case err == nil:
		if old, derr := base64.StdEncoding.DecodeString(strings.ReplaceAll(current.Content, "\n", "")); derr == nil && bytes.Equal(old, f.Content) {
			return nil // already up to date
		}
	case errors.Is(err, errNotFound):
		current.SHA = ""
	default:
		return fmt.Errorf("scm(gh): reading %s on %s: %w", f.Path, branch, err)
	}
	payload := map[string]string{
		"message": message,
		"content": base64.StdEncoding.EncodeToString(f.Content),
		"branch":  branch,
	}
	if current.SHA != "" {
		payload["sha"] = current.SHA
	}
	if err := g.sendJSON(ctx, http.MethodPut, fileURL, payload, nil); err != nil {
		return fmt.Errorf("scm(gh): committing %s to %s: %w", f.Path, branch, err)
	}
	return nil
}

// applyLabels adds the labels that exist and warns about the rest (FR-22):
// it never creates a label and never fails the PR because of one.
func (g *gitHubClient) applyLabels(ctx context.Context, number int, labels []string) []string {
	var warnings, existing []string
	for _, l := range labels {
		var lab struct{}
		err := g.getJSON(ctx, g.repoURL("/labels/"+url.PathEscape(l)), &lab)
		switch {
		case err == nil:
			existing = append(existing, l)
		case errors.Is(err, errNotFound):
			warnings = append(warnings, fmt.Sprintf("Label '%s' not found — skipping.", l))
		default:
			warnings = append(warnings, fmt.Sprintf("Label '%s' could not be checked (%v) — skipping.", l, err))
		}
	}
	if len(existing) > 0 {
		if err := g.sendJSON(ctx, http.MethodPost, g.repoURL(fmt.Sprintf("/issues/%d/labels", number)),
			map[string][]string{"labels": existing}, nil); err != nil {
			warnings = append(warnings, fmt.Sprintf("labels could not be applied: %v", err))
		}
	}
	return warnings
}

func (g *gitHubClient) EnsureComment(ctx context.Context, prID string, body string) error {
	if err := ValidPRID(prID); err != nil {
		return err
	}
	listURL := g.repoURL("/issues/" + prID + "/comments")
	// Paginated: a busy PR has more than the API's default 30 comments, and
	// missing the marker on page 2 meant a duplicate comment every run.
	pages, err := g.getAll(ctx, listURL)
	if err != nil {
		return fmt.Errorf("scm(gh): list comments: %w", err)
	}
	fullBody := prCommentMarker + "\n\n" + body
	for _, raw := range pages {
		var c struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("scm(gh): parse comments: %w", err)
		}
		if strings.Contains(c.Body, prCommentMarker) {
			if err := g.sendJSON(ctx, http.MethodPatch, g.repoURL(fmt.Sprintf("/issues/comments/%d", c.ID)),
				map[string]string{"body": fullBody}, nil); err != nil {
				return fmt.Errorf("scm(gh): update comment: %w", err)
			}
			return nil
		}
	}
	if err := g.sendJSON(ctx, http.MethodPost, listURL, map[string]string{"body": fullBody}, nil); err != nil {
		return fmt.Errorf("scm(gh): create comment: %w", err)
	}
	return nil
}

// ── HTTP plumbing ─────────────────────────────────────────────────────────────

func (g *gitHubClient) repoURL(suffix string) string {
	return g.apiURL + "/repos/" + g.repo + suffix
}

// escapePath escapes each segment of a repository path.
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// escapeRef escapes a branch name for /git/ref/heads/<ref>, keeping its '/'.
func escapeRef(ref string) string { return escapePath(ref) }

var nextLinkRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// getAll GETs a list endpoint and follows its Link: rel="next" pages,
// returning every element.
func (g *gitHubClient) getAll(ctx context.Context, u string) ([]json.RawMessage, error) {
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	next := u + sep + "per_page=100"
	var all []json.RawMessage
	for page := 0; next != "" && page < 50; page++ { // 5000 items is plenty
		body, hdr, err := g.do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		var items []json.RawMessage
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, fmt.Errorf("parsing list page: %w", err)
		}
		all = append(all, items...)
		next = ""
		if m := nextLinkRe.FindStringSubmatch(hdr.Get("Link")); m != nil && strings.HasPrefix(m[1], g.apiURL) {
			next = m[1]
		}
	}
	return all, nil
}

func (g *gitHubClient) getJSON(ctx context.Context, u string, out any) error {
	body, _, err := g.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func (g *gitHubClient) sendJSON(ctx context.Context, method, u string, payload, out any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	body, _, err := g.do(ctx, method, u, b)
	if err != nil || out == nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func (g *gitHubClient) do(ctx context.Context, method, u string, payload []byte) ([]byte, http.Header, error) {
	var rdr *bytes.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequestWithContext(ctx, method, u, rdr)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, u, nil)
	}
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := safeio.ReadAll(resp.Body, safeio.MaxHTTPBody, "github API response")
	if err != nil {
		return nil, nil, fmt.Errorf("reading github API response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, fmt.Errorf("github API %s %s → 404: %w", method, req.URL.Path, errNotFound)
	}
	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("github API %s %s → %d: %s", method, req.URL.Path, resp.StatusCode, truncate(body, 500))
	}
	return body, resp.Header, nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}
