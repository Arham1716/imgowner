package scm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Arham1716/imgowner/internal/safeio"
)

const adoAPI = "api-version=7.1"

// zeroObjectID is the "no previous commit" value ADO expects when a push
// creates a branch.
const zeroObjectID = "0000000000000000000000000000000000000000"

// adoClient implements PRClient for Azure DevOps via the REST API.
// Auth: AZURE_DEVOPS_TOKEN (a PAT with Code read/write and Pull Request
// contribute), or the pipeline's own SYSTEM_ACCESSTOKEN (map
// $(System.AccessToken) into the step's environment; NFR-06).
type adoClient struct {
	token   string
	bearer  bool   // SYSTEM_ACCESSTOKEN is a bearer token; a PAT is basic auth
	orgURL  string // e.g. https://dev.azure.com/myorg
	project string
	repo    string
}

func newADOClient() (*adoClient, error) {
	token, bearer := os.Getenv("AZURE_DEVOPS_TOKEN"), false
	if token == "" {
		token, bearer = os.Getenv("SYSTEM_ACCESSTOKEN"), true
	}
	if token == "" {
		return nil, fmt.Errorf("scm: AZURE_DEVOPS_TOKEN (or SYSTEM_ACCESSTOKEN) not set")
	}
	orgURL := os.Getenv("SYSTEM_TEAMFOUNDATIONSERVERURI")
	project := os.Getenv("SYSTEM_TEAMPROJECT")
	repo := os.Getenv("BUILD_REPOSITORY_NAME")
	if orgURL == "" || project == "" || repo == "" {
		return nil, fmt.Errorf("scm: SYSTEM_TEAMFOUNDATIONSERVERURI / SYSTEM_TEAMPROJECT / BUILD_REPOSITORY_NAME not set")
	}
	return &adoClient{token: token, bearer: bearer, orgURL: strings.TrimRight(orgURL, "/"), project: project, repo: repo}, nil
}

// repoURL builds .../{project}/_apis/git/repositories/{repo}{suffix}. Project
// and repository names often contain spaces in ADO, so both are escaped.
func (a *adoClient) repoURL(suffix string) string {
	return fmt.Sprintf("%s/%s/_apis/git/repositories/%s%s",
		a.orgURL, url.PathEscape(a.project), url.PathEscape(a.repo), suffix)
}

func withAPI(u string) string {
	if strings.Contains(u, "?") {
		return u + "&" + adoAPI
	}
	return u + "?" + adoAPI
}

type adoPR struct {
	PullRequestID int    `json:"pullRequestId"`
	Description   string `json:"description"`
	SourceRefName string `json:"sourceRefName"`
}

func (a *adoClient) OpenOrUpdatePR(ctx context.Context, req PRRequest) (PRResult, error) {
	var res PRResult
	base := req.BaseBranch
	if base == "" {
		var repo struct {
			DefaultBranch string `json:"defaultBranch"`
		}
		if err := a.getJSON(ctx, withAPI(a.repoURL("")), &repo); err != nil {
			return res, fmt.Errorf("scm(ado): reading the default branch: %w", err)
		}
		base = strings.TrimPrefix(repo.DefaultBranch, "refs/heads/")
	}

	// FR-21: find the open PR carrying the marker. The old query used
	// sourceRefName=/targetRefName=, which ADO ignores (the parameters are
	// searchCriteria.*), so every active PR matched and the first one --
	// usually someone else's -- had its title and description replaced.
	existing, err := a.findMarkedPR(ctx, base)
	if err != nil {
		return res, err
	}
	branch := BranchName(req.BranchPrefix)
	if existing != nil {
		branch = strings.TrimPrefix(existing.SourceRefName, "refs/heads/")
	}
	res.Branch = branch

	if err := a.pushFile(ctx, branch, base, req.File, req.CommitMessage); err != nil {
		return res, err
	}

	desc := req.Body + "\n\n" + prCommentMarker
	var pr adoPR
	if existing != nil {
		if err := a.sendJSON(ctx, http.MethodPatch, withAPI(a.repoURL(fmt.Sprintf("/pullrequests/%d", existing.PullRequestID))),
			map[string]string{"title": req.Title, "description": desc}, &pr); err != nil {
			return res, fmt.Errorf("scm(ado): update PR %d: %w", existing.PullRequestID, err)
		}
		pr.PullRequestID = existing.PullRequestID
	} else {
		if err := a.sendJSON(ctx, http.MethodPost, withAPI(a.repoURL("/pullrequests")), map[string]string{
			"title": req.Title, "description": desc,
			"sourceRefName": "refs/heads/" + branch, "targetRefName": "refs/heads/" + base,
		}, &pr); err != nil {
			return res, fmt.Errorf("scm(ado): create PR: %w", err)
		}
		res.Created = true
	}
	// The API's "url" field is a REST URL; people need the web page.
	res.URL = fmt.Sprintf("%s/%s/_git/%s/pullrequest/%d", a.orgURL, url.PathEscape(a.project), url.PathEscape(a.repo), pr.PullRequestID)
	if len(req.Labels) > 0 {
		// ADO PR labels are free-form tags that adding one creates; FR-22
		// forbids creating labels, so they are not applied here.
		res.Warnings = append(res.Warnings, "scm.labels are not applied on Azure DevOps (adding a PR label there creates it)")
	}
	return res, nil
}

func (a *adoClient) findMarkedPR(ctx context.Context, base string) (*adoPR, error) {
	q := "/pullrequests?searchCriteria.status=active&searchCriteria.targetRefName=" + url.QueryEscape("refs/heads/"+base)
	for skip := 0; skip < 5000; skip += 100 {
		var page struct {
			Value []adoPR `json:"value"`
		}
		if err := a.getJSON(ctx, withAPI(a.repoURL(fmt.Sprintf("%s&$top=100&$skip=%d", q, skip))), &page); err != nil {
			return nil, fmt.Errorf("scm(ado): list PRs: %w", err)
		}
		for i := range page.Value {
			if strings.Contains(page.Value[i].Description, prCommentMarker) {
				return &page.Value[i], nil
			}
		}
		if len(page.Value) < 100 {
			return nil, nil
		}
	}
	return nil, nil
}

// refObjectID returns the commit a branch points at, or "" if it doesn't exist.
func (a *adoClient) refObjectID(ctx context.Context, branch string) (string, error) {
	var refs struct {
		Value []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		} `json:"value"`
	}
	if err := a.getJSON(ctx, withAPI(a.repoURL("/refs?filter="+url.QueryEscape("heads/"+branch))), &refs); err != nil {
		return "", err
	}
	for _, r := range refs.Value {
		if r.Name == "refs/heads/"+branch { // the filter is a prefix match
			return r.ObjectID, nil
		}
	}
	return "", nil
}

// pushFile commits f to branch, creating the branch from base if needed. An
// existing branch gets a new commit on top (never a reset).
func (a *adoClient) pushFile(ctx context.Context, branch, base string, f FileChange, message string) error {
	if f.Path == "" {
		return fmt.Errorf("scm(ado): no file to commit")
	}
	head, err := a.refObjectID(ctx, branch)
	if err != nil {
		return fmt.Errorf("scm(ado): reading branch %s: %w", branch, err)
	}
	oldID, parent := head, head
	if head == "" {
		if parent, err = a.refObjectID(ctx, base); err != nil || parent == "" {
			return fmt.Errorf("scm(ado): reading base branch %s: %v", base, err)
		}
		oldID = zeroObjectID
	}
	// Skip the push when the branch already has exactly this content.
	itemURL := a.repoURL("/items?path=" + url.QueryEscape("/"+f.Path) +
		"&versionDescriptor.versionType=commit&versionDescriptor.version=" + parent + "&includeContent=true&$format=octetStream")
	if current, _, err := a.do(ctx, http.MethodGet, withAPI(itemURL), nil); err == nil && bytes.Equal(current, f.Content) {
		return nil
	} else if err != nil && !errors.Is(err, errNotFound) {
		return fmt.Errorf("scm(ado): reading %s: %w", f.Path, err)
	}
	push := map[string]any{
		"refUpdates": []map[string]string{{"name": "refs/heads/" + branch, "oldObjectId": oldID}},
		"commits": []map[string]any{{
			"comment": message,
			"parents": []string{parent},
			"changes": []map[string]any{{
				"changeType": "edit",
				"item":       map[string]string{"path": "/" + f.Path},
				"newContent": map[string]string{"content": string(f.Content), "contentType": "rawtext"},
			}},
		}},
	}
	if err := a.sendJSON(ctx, http.MethodPost, withAPI(a.repoURL("/pushes")), push, nil); err != nil {
		return fmt.Errorf("scm(ado): pushing %s to %s: %w", f.Path, branch, err)
	}
	return nil
}

func (a *adoClient) EnsureComment(ctx context.Context, prID string, body string) error {
	if err := ValidPRID(prID); err != nil {
		return err
	}
	threadsURL := withAPI(a.repoURL("/pullrequests/" + prID + "/threads"))
	var threads struct {
		Value []struct {
			ID       int `json:"id"`
			Comments []struct {
				ID      int    `json:"id"`
				Content string `json:"content"`
			} `json:"comments"`
		} `json:"value"`
	}
	if err := a.getJSON(ctx, threadsURL, &threads); err != nil {
		return fmt.Errorf("scm(ado): list threads: %w", err)
	}

	fullBody := prCommentMarker + "\n\n" + body
	for _, t := range threads.Value {
		for _, c := range t.Comments {
			if strings.Contains(c.Content, prCommentMarker) {
				u := withAPI(a.repoURL(fmt.Sprintf("/pullrequests/%s/threads/%d/comments/%d", prID, t.ID, c.ID)))
				if err := a.sendJSON(ctx, http.MethodPatch, u, map[string]string{"content": fullBody}, nil); err != nil {
					return fmt.Errorf("scm(ado): update comment: %w", err)
				}
				return nil
			}
		}
	}
	if err := a.sendJSON(ctx, http.MethodPost, threadsURL, map[string]any{
		"comments": []map[string]string{{"content": fullBody, "commentType": "text"}},
		"status":   "active",
	}, nil); err != nil {
		return fmt.Errorf("scm(ado): create comment: %w", err)
	}
	return nil
}

func (a *adoClient) getJSON(ctx context.Context, u string, out any) error {
	body, _, err := a.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func (a *adoClient) sendJSON(ctx context.Context, method, u string, payload, out any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	body, _, err := a.do(ctx, method, u, b)
	if err != nil || out == nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func (a *adoClient) do(ctx context.Context, method, u string, payload []byte) ([]byte, http.Header, error) {
	var req *http.Request
	var err error
	if payload != nil {
		req, err = http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, u, nil)
	}
	if err != nil {
		return nil, nil, err
	}
	if a.bearer {
		req.Header.Set("Authorization", "Bearer "+a.token)
	} else {
		req.SetBasicAuth("", a.token) // a PAT is the password with an empty username
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := safeio.ReadAll(resp.Body, safeio.MaxHTTPBody, "ADO API response")
	if err != nil {
		return nil, nil, fmt.Errorf("reading ADO API response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, fmt.Errorf("ADO API %s %s → 404: %w", method, req.URL.Path, errNotFound)
	}
	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("ADO API %s %s → %d: %s", method, req.URL.Path, resp.StatusCode, truncate(body, 500))
	}
	return body, resp.Header, nil
}
