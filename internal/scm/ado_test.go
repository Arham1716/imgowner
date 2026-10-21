package scm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestADOClient(orgURL string) *adoClient {
	return &adoClient{token: "test-token", orgURL: orgURL, project: "proj", repo: "repo"}
}

// Same idempotency contract as GitHub (FR-24), implemented against ADO's
// thread/comment model instead of flat issue comments: find a thread whose
// comment carries the marker and PATCH it, or start a new thread.
func TestADO_EnsureComment_CreatesThreadWhenNoneExists(t *testing.T) {
	var threadCreated bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/threads"):
			_, _ = w.Write([]byte(`{"value":[]}`))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/threads"):
			threadCreated = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestADOClient(srv.URL)
	if err := c.EnsureComment(context.Background(), "42", "report body"); err != nil {
		t.Fatalf("EnsureComment: %v", err)
	}
	if !threadCreated {
		t.Error("expected a new thread to be created when no marked comment exists")
	}
}

func TestADO_EnsureComment_UpdatesExistingMarkedComment(t *testing.T) {
	var patchedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/threads"):
			_, _ = w.Write([]byte(`{"value":[
				{"id": 5, "comments": [{"id": 1, "content": "unrelated"}]},
				{"id": 6, "comments": [{"id": 2, "content": "` + prCommentMarker + `\n\nold"}]}
			]}`))
		case r.Method == http.MethodPatch:
			patchedPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost:
			t.Error("must not start a new thread when a marked comment already exists")
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestADOClient(srv.URL)
	if err := c.EnsureComment(context.Background(), "42", "new report"); err != nil {
		t.Fatalf("EnsureComment: %v", err)
	}
	// Thread 6 holds the marked comment (id 2); thread 5's unrelated comment must be skipped.
	if !strings.Contains(patchedPath, "/threads/6/comments/2") {
		t.Errorf("expected PATCH to thread 6 comment 2 (the marked one), got path %q", patchedPath)
	}
}

func TestADO_OpenOrUpdatePR_CreatesWhenNoneActive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pullrequests"):
			_, _ = w.Write([]byte(`{"count":0,"value":[]}`))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/pullrequests"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"url":"https://dev.azure.com/org/proj/_apis/git/repositories/repo/pullrequests/3"}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestADOClient(srv.URL)
	url, err := c.OpenOrUpdatePR(context.Background(), PRRequest{
		HeadBranch: "imgowner/pin-updates", BaseBranch: "main", Title: "t", Body: "b",
	})
	if err != nil {
		t.Fatalf("OpenOrUpdatePR: %v", err)
	}
	if !strings.Contains(url, "/pullrequests/3") {
		t.Errorf("expected the created PR's url, got %q", url)
	}
}

func TestADO_OpenOrUpdatePR_UpdatesWhenOneActive(t *testing.T) {
	var patched bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/pullrequests"):
			_, _ = w.Write([]byte(`{"count":1,"value":[{"pullRequestId":11,"url":"https://dev.azure.com/x/11"}]}`))
		case r.Method == http.MethodPatch:
			patched = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost:
			t.Error("must not create a second PR when one is already active for this branch")
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestADOClient(srv.URL)
	_, err := c.OpenOrUpdatePR(context.Background(), PRRequest{
		HeadBranch: "imgowner/pin-updates", BaseBranch: "main", Title: "t", Body: "b",
	})
	if err != nil {
		t.Fatalf("OpenOrUpdatePR: %v", err)
	}
	if !patched {
		t.Error("expected the existing active PR to be updated via PATCH")
	}
}
