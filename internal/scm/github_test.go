package scm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestGitHubClient(apiURL string) *gitHubClient {
	return &gitHubClient{token: "test-token", repo: "owner/repo", apiURL: apiURL}
}

// The idempotent-comment contract (FR-24) is the part most likely to regress
// silently: find an existing <!-- imgowner --> comment and PATCH it, or POST a
// new one only when none exists. A bug here means either a growing pile of
// duplicate comments on every CI run, or a comment that's never found and
// updated at all.
func TestEnsureComment_CreatesWhenNoneExists(t *testing.T) {
	var posted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/issues/42/comments"):
			_, _ = w.Write([]byte(`[]`)) // no existing comments
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/issues/42/comments"):
			posted = true
			body, _ := decodeJSON[map[string]string](r)
			if !strings.Contains(body["body"], prCommentMarker) {
				t.Error("posted comment body must contain the imgowner marker")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestGitHubClient(srv.URL)
	if err := c.EnsureComment(context.Background(), "42", "report body"); err != nil {
		t.Fatalf("EnsureComment: %v", err)
	}
	if !posted {
		t.Error("expected a POST to create a new comment")
	}
}

func TestEnsureComment_UpdatesExistingMarkedComment(t *testing.T) {
	var patchedID string
	var posted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/issues/42/comments"):
			_, _ = w.Write([]byte(`[
				{"id": 1, "body": "some unrelated comment"},
				{"id": 2, "body": "` + prCommentMarker + `\n\nold report"}
			]`))
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/issues/comments/2"):
			patchedID = "2"
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost:
			posted = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestGitHubClient(srv.URL)
	if err := c.EnsureComment(context.Background(), "42", "new report body"); err != nil {
		t.Fatalf("EnsureComment: %v", err)
	}
	if patchedID != "2" {
		t.Errorf("expected PATCH to comment id 2 (the marked one), got patchedID=%q", patchedID)
	}
	if posted {
		t.Error("an existing marked comment must be updated, not duplicated with a new POST")
	}
}

// A 401/404/500 from the API must surface as a Go error the caller can act on,
// not be swallowed into a successful-looking return.
func TestEnsureComment_APIErrorIsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()

	c := newTestGitHubClient(srv.URL)
	err := c.EnsureComment(context.Background(), "42", "body")
	if err == nil {
		t.Fatal("expected an error on 401 Unauthorized, got nil")
	}
}

func TestOpenOrUpdatePR_CreatesWhenNoneOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pulls"):
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"html_url":"https://github.com/owner/repo/pull/7"}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestGitHubClient(srv.URL)
	url, err := c.OpenOrUpdatePR(context.Background(), PRRequest{
		HeadBranch: "imgowner/pin-updates", BaseBranch: "main", Title: "t", Body: "b",
	})
	if err != nil {
		t.Fatalf("OpenOrUpdatePR: %v", err)
	}
	if url != "https://github.com/owner/repo/pull/7" {
		t.Errorf("expected the created PR's URL, got %q", url)
	}
}

func TestOpenOrUpdatePR_UpdatesWhenOneAlreadyOpen(t *testing.T) {
	var patched bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pulls"):
			_, _ = w.Write([]byte(`[{"number":9,"html_url":"https://github.com/owner/repo/pull/9"}]`))
		case r.Method == http.MethodPatch && strings.HasSuffix(r.URL.Path, "/pulls/9"):
			patched = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost:
			t.Error("must not open a second PR when one is already open for this branch")
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestGitHubClient(srv.URL)
	url, err := c.OpenOrUpdatePR(context.Background(), PRRequest{
		HeadBranch: "imgowner/pin-updates", BaseBranch: "main", Title: "t", Body: "b",
	})
	if err != nil {
		t.Fatalf("OpenOrUpdatePR: %v", err)
	}
	if !patched {
		t.Error("expected the existing PR to be updated via PATCH")
	}
	if url != "https://github.com/owner/repo/pull/9" {
		t.Errorf("expected the existing PR's URL, got %q", url)
	}
}

func decodeJSON[T any](r *http.Request) (T, error) {
	var out T
	err := json.NewDecoder(r.Body).Decode(&out)
	return out, err
}
