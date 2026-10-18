package scm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// adoClient implements PRClient for Azure DevOps via the REST API.
// Auth: AZURE_DEVOPS_TOKEN env var (PAT with Code, Pull Request R/W).
type adoClient struct {
	token   string
	orgURL  string // e.g. https://dev.azure.com/myorg
	project string
	repo    string
}

func newADOClient() (*adoClient, error) {
	token := os.Getenv("AZURE_DEVOPS_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("scm: AZURE_DEVOPS_TOKEN not set")
	}
	orgURL := os.Getenv("SYSTEM_TEAMFOUNDATIONSERVERURI")
	project := os.Getenv("SYSTEM_TEAMPROJECT")
	repo := os.Getenv("BUILD_REPOSITORY_NAME")
	if orgURL == "" || project == "" || repo == "" {
		return nil, fmt.Errorf("scm: SYSTEM_TEAMFOUNDATIONSERVERURI / SYSTEM_TEAMPROJECT / BUILD_REPOSITORY_NAME not set")
	}
	return &adoClient{token: token, orgURL: strings.TrimRight(orgURL, "/"), project: project, repo: repo}, nil
}

func (a *adoClient) OpenOrUpdatePR(ctx context.Context, req PRRequest) (string, error) {
	apiVer := "api-version=7.1"
	listURL := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/pullrequests?sourceRefName=refs/heads/%s&targetRefName=refs/heads/%s&status=active&%s",
		a.orgURL, a.project, a.repo, req.HeadBranch, req.BaseBranch, apiVer)

	data, err := a.adoGET(ctx, listURL)
	if err != nil {
		return "", fmt.Errorf("scm(ado): list PRs: %w", err)
	}
	var list struct {
		Count int `json:"count"`
		Value []struct {
			PullRequestID int    `json:"pullRequestId"`
			URL           string `json:"url"`
		} `json:"value"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return "", fmt.Errorf("scm(ado): parse PR list: %w", err)
	}

	if list.Count > 0 {
		id := list.Value[0].PullRequestID
		patchURL := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/pullrequests/%d?%s",
			a.orgURL, a.project, a.repo, id, apiVer)
		body := map[string]string{"title": req.Title, "description": req.Body + "\n\n" + prCommentMarker}
		if _, err := a.adoPATCH(ctx, patchURL, body); err != nil {
			return "", fmt.Errorf("scm(ado): update PR: %w", err)
		}
		return patchURL, nil
	}

	createURL := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/pullrequests?%s",
		a.orgURL, a.project, a.repo, apiVer)
	body := map[string]any{
		"title":         req.Title,
		"description":   req.Body + "\n\n" + prCommentMarker,
		"sourceRefName": "refs/heads/" + req.HeadBranch,
		"targetRefName": "refs/heads/" + req.BaseBranch,
	}
	resp, err := a.adoPOST(ctx, createURL, body)
	if err != nil {
		return "", fmt.Errorf("scm(ado): create PR: %w", err)
	}
	var created struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(resp, &created); err != nil {
		return "", fmt.Errorf("scm(ado): parse create response: %w", err)
	}
	return created.URL, nil
}

func (a *adoClient) EnsureComment(ctx context.Context, prID string, body string) error {
	apiVer := "api-version=7.1"
	threadsURL := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/pullrequests/%s/threads?%s",
		a.orgURL, a.project, a.repo, prID, apiVer)

	data, err := a.adoGET(ctx, threadsURL)
	if err != nil {
		return fmt.Errorf("scm(ado): list threads: %w", err)
	}
	var threads struct {
		Value []struct {
			ID       int `json:"id"`
			Comments []struct {
				ID      int    `json:"id"`
				Content string `json:"content"`
			} `json:"comments"`
		} `json:"value"`
	}
	if err := json.Unmarshal(data, &threads); err != nil {
		return fmt.Errorf("scm(ado): parse threads: %w", err)
	}

	fullBody := prCommentMarker + "\n\n" + body

	for _, t := range threads.Value {
		for _, c := range t.Comments {
			if strings.Contains(c.Content, prCommentMarker) {
				patchURL := fmt.Sprintf("%s/%s/_apis/git/repositories/%s/pullrequests/%s/threads/%d/comments/%d?%s",
					a.orgURL, a.project, a.repo, prID, t.ID, c.ID, apiVer)
				_, err := a.adoPATCH(ctx, patchURL, map[string]string{"content": fullBody})
				return err
			}
		}
	}

	_, err = a.adoPOST(ctx, threadsURL, map[string]any{
		"comments": []map[string]string{{"content": fullBody, "commentType": "text"}},
		"status":   "active",
	})
	return err
}

func (a *adoClient) adoGET(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return a.do(req)
}

func (a *adoClient) adoPOST(ctx context.Context, url string, payload any) ([]byte, error) {
	return a.adoSend(ctx, http.MethodPost, url, payload)
}

func (a *adoClient) adoPATCH(ctx context.Context, url string, payload any) ([]byte, error) {
	return a.adoSend(ctx, http.MethodPatch, url, payload)
}

func (a *adoClient) adoSend(ctx context.Context, method, url string, payload any) ([]byte, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return a.do(req)
}

func (a *adoClient) do(req *http.Request) ([]byte, error) {
	req.SetBasicAuth("", a.token) // ADO uses PAT as password with empty username
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ADO API %s %s → %d: %s", req.Method, req.URL, resp.StatusCode, body)
	}
	return body, nil
}
