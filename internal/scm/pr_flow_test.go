package scm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeGitHub is a small stateful GitHub: branches, one file, pull requests,
// labels and issue comments, enough to exercise the whole PR flow.
type fakeGitHub struct {
	mu       sync.Mutex
	t        *testing.T
	branches map[string]string // branch -> head sha
	files    map[string]string // branch -> Dockerfile content
	pulls    []map[string]any
	labels   map[string]bool
	applied  map[int][]string
	commits  int
}

func newFakeGitHub(t *testing.T) (*fakeGitHub, *gitHubClient) {
	f := &fakeGitHub{
		t:        t,
		branches: map[string]string{"main": "sha-main"},
		files:    map[string]string{"main": "FROM debian:12\nRUN apt-get install -y curl=1.0\n"},
		labels:   map[string]bool{"security": true},
		applied:  map[int][]string{},
	}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, &gitHubClient{token: "t", repo: "owner/repo", apiURL: srv.URL}
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/repos/owner/repo")
	reply := func(code int, v any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch {
	case r.Method == "GET" && p == "":
		reply(200, map[string]string{"default_branch": "main"})
	case r.Method == "GET" && p == "/pulls":
		var open []map[string]any
		for _, pr := range f.pulls {
			if pr["state"] == "open" && pr["base"] == r.URL.Query().Get("base") {
				open = append(open, pr)
			}
		}
		reply(200, open)
	case r.Method == "POST" && p == "/pulls":
		head := body["head"].(string)
		if _, ok := f.branches[head]; !ok {
			reply(422, map[string]string{"message": "Validation Failed: head invalid"})
			return
		}
		n := 100 + len(f.pulls)
		pr := map[string]any{"number": n, "html_url": fmt.Sprintf("https://github.com/owner/repo/pull/%d", n),
			"body": body["body"], "title": body["title"], "state": "open", "base": body["base"],
			"head": map[string]any{"ref": head, "repo": map[string]string{"full_name": "owner/repo"}}}
		f.pulls = append(f.pulls, pr)
		reply(201, pr)
	case r.Method == "PATCH" && strings.HasPrefix(p, "/pulls/"):
		for _, pr := range f.pulls {
			if fmt.Sprint(pr["number"]) == strings.TrimPrefix(p, "/pulls/") {
				pr["title"], pr["body"] = body["title"], body["body"]
				reply(200, pr)
				return
			}
		}
		reply(404, nil)
	case r.Method == "GET" && strings.HasPrefix(p, "/git/ref/heads/"):
		b := strings.TrimPrefix(p, "/git/ref/heads/")
		if sha, ok := f.branches[b]; ok {
			reply(200, map[string]any{"object": map[string]string{"sha": sha}})
			return
		}
		reply(404, nil)
	case r.Method == "POST" && p == "/git/refs":
		b := strings.TrimPrefix(body["ref"].(string), "refs/heads/")
		f.branches[b] = body["sha"].(string)
		f.files[b] = f.files["main"]
		reply(201, nil)
	case r.Method == "GET" && p == "/contents/app/Dockerfile":
		b := r.URL.Query().Get("ref")
		reply(200, map[string]string{"sha": "blob-" + b, "content": base64.StdEncoding.EncodeToString([]byte(f.files[b]))})
	case r.Method == "PUT" && p == "/contents/app/Dockerfile":
		b := body["branch"].(string)
		if b == "main" {
			f.t.Error("committed straight to the base branch")
		}
		content, _ := base64.StdEncoding.DecodeString(body["content"].(string))
		f.files[b] = string(content)
		f.commits++
		reply(200, nil)
	case r.Method == "GET" && strings.HasPrefix(p, "/labels/"):
		if f.labels[strings.TrimPrefix(p, "/labels/")] {
			reply(200, map[string]string{})
			return
		}
		reply(404, nil)
	case r.Method == "POST" && strings.HasSuffix(p, "/labels"):
		var n int
		_, _ = fmt.Sscanf(p, "/issues/%d/labels", &n)
		for _, l := range body["labels"].([]any) {
			f.applied[n] = append(f.applied[n], l.(string))
		}
		reply(200, nil)
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
		reply(500, nil)
	}
}

func pinPR(content string) PRRequest {
	return PRRequest{
		BranchPrefix: "fix/os-pins", Title: "chore: update pins", Body: "updates",
		Labels: []string{"security", "dependencies"},
		File:   FileChange{Path: "app/Dockerfile", Content: []byte(content)}, CommitMessage: "update pins",
	}
}

// The v0.5.0 flow never pushed a branch (GitHub answered 422) and matched
// "existing" PRs with a filter GitHub ignores. With a decoy PR open, the new
// flow must create the branch, commit the file, open a PR, apply the label
// that exists and warn about the one that doesn't -- and leave the decoy alone.
func TestOpenOrUpdatePR_GitHub_CreatesBranchCommitAndPR(t *testing.T) {
	f, c := newFakeGitHub(t)
	f.branches["feature"] = "sha-f"
	f.pulls = append(f.pulls, map[string]any{"number": 7, "state": "open", "base": "main", "title": "DECOY", "body": "someone's work",
		"head": map[string]any{"ref": "feature", "repo": map[string]string{"full_name": "owner/repo"}}})

	res, err := c.OpenOrUpdatePR(context.Background(), pinPR("FROM debian:12\nRUN apt-get install -y curl=1.1\n"))
	if err != nil {
		t.Fatalf("OpenOrUpdatePR: %v", err)
	}
	if !res.Created || res.Branch != "fix/os-pins" || !strings.HasSuffix(res.URL, "/pull/101") {
		t.Errorf("result %+v", res)
	}
	if !strings.Contains(f.files["fix/os-pins"], "curl=1.1") || f.files["main"] != "FROM debian:12\nRUN apt-get install -y curl=1.0\n" {
		t.Errorf("file not committed to the PR branch only: %v", f.files)
	}
	if f.pulls[0]["title"] != "DECOY" || f.pulls[0]["body"] != "someone's work" {
		t.Errorf("the decoy PR was modified: %v", f.pulls[0])
	}
	if got := f.applied[101]; len(got) != 1 || got[0] != "security" {
		t.Errorf("labels applied: %v", got)
	}
	if len(res.Warnings) != 1 || res.Warnings[0] != "Label 'dependencies' not found — skipping." {
		t.Errorf("warnings: %v", res.Warnings)
	}
}

// FR-21: a second run updates the marked PR on its own branch.
func TestOpenOrUpdatePR_GitHub_UpdatesTheMarkedPR(t *testing.T) {
	f, c := newFakeGitHub(t)
	if _, err := c.OpenOrUpdatePR(context.Background(), pinPR("v1")); err != nil {
		t.Fatal(err)
	}
	res, err := c.OpenOrUpdatePR(context.Background(), pinPR("v2"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Created || len(f.pulls) != 1 || f.files["fix/os-pins"] != "v2" || f.commits != 2 {
		t.Errorf("second run: res=%+v pulls=%d file=%q commits=%d", res, len(f.pulls), f.files["fix/os-pins"], f.commits)
	}
	// Same content again: no empty commit.
	if _, err := c.OpenOrUpdatePR(context.Background(), pinPR("v2")); err != nil {
		t.Fatal(err)
	}
	if f.commits != 2 {
		t.Errorf("an unchanged file was committed again (%d commits)", f.commits)
	}
}

// A marked PR from a fork is not ours to update.
func TestOpenOrUpdatePR_GitHub_IgnoresAMarkedPRFromAFork(t *testing.T) {
	f, c := newFakeGitHub(t)
	f.pulls = append(f.pulls, map[string]any{"number": 5, "state": "open", "base": "main", "title": "fork", "body": "x " + prCommentMarker,
		"head": map[string]any{"ref": "fix/os-pins", "repo": map[string]string{"full_name": "attacker/repo"}}})
	res, err := c.OpenOrUpdatePR(context.Background(), pinPR("v1"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || f.pulls[0]["title"] != "fork" {
		t.Errorf("the fork's PR was treated as ours: %+v", res)
	}
}

func TestBranchName(t *testing.T) {
	for in, want := range map[string]string{"fix/os-pins": "fix/os-pins", "imgowner/": "imgowner/pin-updates", "": "imgowner/pin-updates"} {
		if got := BranchName(in); got != want {
			t.Errorf("BranchName(%q) = %q, want %q", in, got, want)
		}
	}
}

// The marker on page 2 of a busy PR's comments used to be missed, adding a
// duplicate comment every run.
func TestEnsureComment_GitHub_FollowsPagination(t *testing.T) {
	var patched, posted bool
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Query().Get("page") == "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/owner/repo/issues/42/comments?per_page=100&page=2>; rel="next"`, srvURL))
			_, _ = w.Write([]byte(`[{"id":1,"body":"unrelated"}]`))
		case r.Method == "GET":
			_, _ = w.Write([]byte(`[{"id":2,"body":"` + prCommentMarker + ` old"}]`))
		case r.Method == "PATCH" && strings.HasSuffix(r.URL.Path, "/issues/comments/2"):
			patched = true
			_, _ = w.Write([]byte(`{}`))
		case r.Method == "POST":
			posted = true
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	srvURL = srv.URL
	c := &gitHubClient{token: "t", repo: "owner/repo", apiURL: srv.URL}
	if err := c.EnsureComment(context.Background(), "42", "new"); err != nil {
		t.Fatal(err)
	}
	if !patched || posted {
		t.Errorf("patched=%v posted=%v: the page-2 marker was missed", patched, posted)
	}
}

func TestEnsureComment_RejectsANonNumericPRID(t *testing.T) {
	c := &gitHubClient{token: "t", repo: "owner/repo", apiURL: "http://127.0.0.1:1"}
	for _, id := range []string{"1/../../user", "abc", "", "0", "12 34"} {
		if err := c.EnsureComment(context.Background(), id, "x"); err == nil || !strings.Contains(err.Error(), "invalid pull request id") {
			t.Errorf("EnsureComment(%q) = %v", id, err)
		}
	}
}

// ADO: the PR search must use searchCriteria.* (the old parameters are
// ignored by ADO, so any active PR matched), the change must be pushed to
// the imgowner branch with the base as parent, and the returned URL must be
// the web page, with project names escaped.
func TestOpenOrUpdatePR_ADO_PushesAndCreates(t *testing.T) {
	var pushed map[string]any
	var created bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "GET" && strings.HasSuffix(p, "/repositories/my%20repo") || strings.HasSuffix(p, "/repositories/my repo"):
			_, _ = w.Write([]byte(`{"defaultBranch":"refs/heads/develop"}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/pullrequests"):
			if r.URL.Query().Get("searchCriteria.targetRefName") != "refs/heads/develop" || r.URL.Query().Get("searchCriteria.status") != "active" {
				t.Errorf("PR search without searchCriteria: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"value":[{"pullRequestId":3,"description":"someone else's","sourceRefName":"refs/heads/feature"}]}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/refs"):
			if strings.Contains(r.URL.Query().Get("filter"), "develop") {
				_, _ = w.Write([]byte(`{"value":[{"name":"refs/heads/develop","objectId":"base-sha"}]}`))
			} else {
				_, _ = w.Write([]byte(`{"value":[]}`))
			}
		case r.Method == "GET" && strings.HasSuffix(p, "/items"):
			_, _ = w.Write([]byte("old content"))
		case r.Method == "POST" && strings.HasSuffix(p, "/pushes"):
			_ = json.NewDecoder(r.Body).Decode(&pushed)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == "POST" && strings.HasSuffix(p, "/pullrequests"):
			created = true
			_, _ = w.Write([]byte(`{"pullRequestId":12}`))
		case r.Method == "PATCH":
			t.Error("an unmarked PR was updated")
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	defer srv.Close()
	c := &adoClient{token: "t", orgURL: srv.URL, project: "My Project", repo: "my repo"}
	res, err := c.OpenOrUpdatePR(context.Background(), pinPR("new content"))
	if err != nil {
		t.Fatal(err)
	}
	if !created || res.URL != srv.URL+"/My%20Project/_git/my%20repo/pullrequest/12" {
		t.Errorf("created=%v url=%q", created, res.URL)
	}
	ref := pushed["refUpdates"].([]any)[0].(map[string]any)
	commit := pushed["commits"].([]any)[0].(map[string]any)
	if ref["name"] != "refs/heads/fix/os-pins" || ref["oldObjectId"] != zeroObjectID || commit["parents"].([]any)[0] != "base-sha" {
		t.Errorf("push: %v", pushed)
	}
}
