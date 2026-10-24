package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/history"
	"github.com/Arham1716/imgowner/internal/pins"
)

type fixture struct {
	t      *testing.T
	srv    *Server
	ts     *httptest.Server
	store  *history.Store
	client *http.Client
}

// newFixture starts the real handler pipeline on a loopback test listener, with
// a client that does not follow redirects (so the token exchange is visible).
func newFixture(t *testing.T) *fixture {
	t.Helper()
	store, err := history.Open(filepath.Join(t.TempDir(), "h"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	srv.setAddr(ts.Listener.Addr().String())
	return &fixture{
		t: t, srv: srv, ts: ts, store: store,
		client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

func (f *fixture) do(method, path, host, cookie string) *http.Response {
	f.t.Helper()
	req, err := http.NewRequest(method, f.ts.URL+path, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// login redeems the launch token and returns the session cookie value.
func (f *fixture) login() string {
	f.t.Helper()
	resp := f.do("GET", "/?token="+url.QueryEscape(f.srv.launchToken), "", "")
	if resp.StatusCode != http.StatusSeeOther {
		f.t.Fatalf("token exchange status = %d, want 303", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			return c.Value
		}
	}
	f.t.Fatal("token exchange set no session cookie")
	return ""
}

func (f *fixture) addScan(in history.Input) string {
	f.t.Helper()
	id, err := f.store.Append(history.NewRecord(in))
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ── NFR-10: Host, token, CSP ─────────────────────────────────────────────────

func TestHostCheck_RejectsNonLoopbackHosts(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	_, port, _ := strings.Cut(f.ts.Listener.Addr().String(), ":")
	for _, host := range []string{
		"evil.example:" + port, // DNS rebinding
		"evil.example",         // no port
		"127.0.0.1",            // right name, missing port
		"127.0.0.2:" + port,    // other loopback address
		"localhost.evil.example:" + port,
		"127.0.0.1:1", // right name, wrong port
		"",            // handled by the client as the default; covered below
	} {
		if host == "" {
			continue
		}
		resp := f.do("GET", "/api/scans", host, cookie)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Host %q: status %d, want 403 (even with a valid session)", host, resp.StatusCode)
		}
	}
}

func TestHostCheck_AcceptsLoopbackAndLocalhost(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	_, port, _ := strings.Cut(f.ts.Listener.Addr().String(), ":")
	for _, host := range []string{"127.0.0.1:" + port, "localhost:" + port, "LOCALHOST:" + port} {
		if resp := f.do("GET", "/api/scans", host, cookie); resp.StatusCode != http.StatusOK {
			t.Errorf("Host %q: status %d, want 200", host, resp.StatusCode)
		}
	}
}

func TestAuth_NoCookieIsRefusedEverywhere(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/", "/api/scans", "/api/scans/20260101T000000.000000000Z-deadbeef", "/api/pins/latest", "/index.html"} {
		if resp := f.do("GET", p, "", ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a session: %d, want 401", p, resp.StatusCode)
		}
	}
}

func TestAuth_WrongCookieIsRefused(t *testing.T) {
	f := newFixture(t)
	if resp := f.do("GET", "/api/scans", "", "not-the-session"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", resp.StatusCode)
	}
	// The launch token is not the session token.
	if resp := f.do("GET", "/api/scans", "", f.srv.launchToken); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the launch token must not work as a session cookie, got %d", resp.StatusCode)
	}
}

func TestAuth_LaunchTokenIsOneTime(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	// Second redemption -- e.g. by someone who read the URL off the process
	// list after the real browser opened it -- is refused.
	resp := f.do("GET", "/?token="+url.QueryEscape(f.srv.launchToken), "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("reused launch token: %d, want 401", resp.StatusCode)
	}
	// ...and the first browser's session keeps working.
	if resp := f.do("GET", "/api/scans", "", cookie); resp.StatusCode != http.StatusOK {
		t.Errorf("session after exchange: %d, want 200", resp.StatusCode)
	}
}

func TestAuth_WrongLaunchTokenDoesNotBurnTheRealOne(t *testing.T) {
	f := newFixture(t)
	if resp := f.do("GET", "/?token=guess", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: %d, want 401", resp.StatusCode)
	}
	f.login() // the real token must still work
}

// The token must not stay in the address bar, history or Referer.
func TestAuth_ExchangeRedirectsToAURLWithoutTheToken(t *testing.T) {
	f := newFixture(t)
	resp := f.do("GET", "/?token="+url.QueryEscape(f.srv.launchToken), "", "")
	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "token") || loc != "/" {
		t.Errorf("Location = %q, want a bare /", loc)
	}
	var c *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			c = ck
		}
	}
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Errorf("session cookie must be HttpOnly, SameSite=Strict, Path=/; got %+v", c)
	}
	if c != nil && c.Value == f.srv.launchToken {
		t.Error("the cookie must hold a separate session value, not the launch token")
	}
}

func TestTokens_AreLongAndDistinct(t *testing.T) {
	f := newFixture(t)
	if len(f.srv.launchToken) < 40 || len(f.srv.sessionToken) < 40 {
		t.Errorf("tokens too short: %d / %d chars", len(f.srv.launchToken), len(f.srv.sessionToken))
	}
	if f.srv.launchToken == f.srv.sessionToken {
		t.Error("launch and session tokens must differ")
	}
	g := newFixture(t)
	if g.srv.launchToken == f.srv.launchToken {
		t.Error("each server must generate its own tokens")
	}
}

func TestSecurityHeaders_PresentOnEveryResponse(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	reqs := []*http.Response{
		f.do("GET", "/", "", cookie),
		f.do("GET", "/api/scans", "", cookie),
		f.do("GET", "/api/nope", "", cookie),
		f.do("GET", "/api/scans", "", ""),                   // 401
		f.do("GET", "/api/scans", "evil.example:1", cookie), // 403
		f.do("POST", "/api/scans", "", cookie),              // 405
	}
	for _, resp := range reqs {
		h := resp.Header
		csp := h.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP missing %q (got %q)", resp.Request.URL.Path, want, csp)
			}
		}
		// Nothing may be loadable from an external origin.
		if strings.Contains(csp, "http:") || strings.Contains(csp, "https:") || strings.Contains(csp, "*") || strings.Contains(csp, "unsafe-") {
			t.Errorf("CSP permits something external or unsafe: %q", csp)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" ||
			h.Get("Referrer-Policy") != "no-referrer" || h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: missing a hardening header: %v", resp.Request.URL.Path, h)
		}
		if h.Get("Access-Control-Allow-Origin") != "" {
			t.Error("no CORS headers may ever be sent")
		}
	}
}

func TestCrossSiteFetchIsRefused(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	req, _ := http.NewRequest("GET", f.ts.URL+"/api/scans", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site fetch: %d, want 403", resp.StatusCode)
	}
}

// ── FR-38: read-only ─────────────────────────────────────────────────────────

func TestReadOnly_NonGetMethodsGet405OnEveryPathAndChangeNothing(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	id := f.addScan(history.Input{Command: "attribute", Image: "x"})
	before, _, _ := f.store.List()

	paths := []string{"/", "/api/scans", "/api/scans/" + id, "/api/pins/latest", "/api/unknown", "/anything", "/api/scans/../../etc"}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"} {
		for _, p := range paths {
			resp := f.do(m, p, "", cookie)
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: %d, want 405", m, p, resp.StatusCode)
			}
			if a := resp.Header.Get("Allow"); !strings.Contains(a, "GET") || strings.Contains(a, "POST") {
				t.Errorf("%s %s: Allow = %q", m, p, a)
			}
		}
	}
	after, _, _ := f.store.List()
	if len(after) != len(before) {
		t.Errorf("history changed under non-GET requests: %d -> %d records", len(before), len(after))
	}
	if _, err := f.store.Get(id); err != nil {
		t.Errorf("the record must still exist: %v", err)
	}
}

// ── API behaviour ────────────────────────────────────────────────────────────

func getJSON(t *testing.T, f *fixture, path, cookie string, v any) *http.Response {
	t.Helper()
	resp := f.do("GET", path, "", cookie)
	if v != nil {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatalf("GET %s: decoding: %v", path, err)
		}
	}
	return resp
}

func TestScans_ListsNewestFirstWithRepositoryAndFilters(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	base := time.Now().UTC().Add(-3 * time.Hour)
	for i, img := range []string{"reg.local/app:1", "reg.local/app:2", "reg.local/other@sha256:abc", "localhost:5000/app:9"} {
		i := i
		f.store = mustSetClock(t, f.store, base.Add(time.Duration(i)*time.Minute))
		_ = f.addScan(history.Input{Command: "attribute", Image: img})
	}
	f.srv.store = f.store

	var out struct {
		Scans []struct {
			Image      string         `json:"image"`
			Repository string         `json:"repository"`
			Counts     map[string]int `json:"counts"`
		} `json:"scans"`
	}
	getJSON(t, f, "/api/scans", cookie, &out)
	if len(out.Scans) != 4 || out.Scans[0].Image != "localhost:5000/app:9" {
		t.Fatalf("scans = %+v, want 4, newest first", out.Scans)
	}
	want := map[string]string{
		"reg.local/app:1": "reg.local/app", "reg.local/other@sha256:abc": "reg.local/other",
		"localhost:5000/app:9": "localhost:5000/app",
	}
	for _, s := range out.Scans {
		if w, ok := want[s.Image]; ok && s.Repository != w {
			t.Errorf("repository of %s = %q, want %q", s.Image, s.Repository, w)
		}
	}

	var filtered struct {
		Scans []struct{ Image string } `json:"scans"`
	}
	getJSON(t, f, "/api/scans?repo=reg.local/app", cookie, &filtered)
	if len(filtered.Scans) != 2 {
		t.Errorf("repo filter returned %d scans, want 2", len(filtered.Scans))
	}
	getJSON(t, f, "/api/scans?limit=1", cookie, &filtered)
	if len(filtered.Scans) != 1 {
		t.Errorf("limit=1 returned %d scans", len(filtered.Scans))
	}
}

func TestScans_EmptyStoreIsAnEmptyListNotNull(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	resp := f.do("GET", "/api/scans", "", cookie)
	if body := readBody(t, resp); !strings.Contains(body, `"scans":[]`) {
		t.Errorf("empty store should list [], got %s", body)
	}
}

// NFR-13: bad query parameters are a structured 400, never a panic or a 500.
func TestScans_BadParametersAre400WithTheOffendingParam(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	for q, param := range map[string]string{
		"limit=0": "limit", "limit=-1": "limit", "limit=999999": "limit", "limit=abc": "limit",
		"days=0": "days", "days=x": "days", "days=99999": "days",
		"repo=" + strings.Repeat("a", maxRepoParam+1): "repo",
		"repo=%00": "repo", "repo=a%0Ab": "repo",
	} {
		var e apiError
		resp := getJSON(t, f, "/api/scans?"+q, cookie, &e)
		if resp.StatusCode != http.StatusBadRequest || e.Param != param {
			t.Errorf("?%.40s: status %d param %q, want 400 / %q", q, resp.StatusCode, e.Param, param)
		}
	}
}

func TestScan_ReturnsTheFullRecord(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	id := f.addScan(history.Input{
		Command: "attribute", Image: "x",
		Findings: []attribution.Finding{{CVE: "CVE-1", Owner: attribution.OwnerAddedOS, Package: "curl"}},
	})
	var rec history.Record
	resp := getJSON(t, f, "/api/scans/"+id, cookie, &rec)
	if resp.StatusCode != 200 || len(rec.Findings) != 1 || rec.Findings[0].CVE != "CVE-1" {
		t.Errorf("status %d record %+v", resp.StatusCode, rec)
	}
}

func TestScan_UnknownAndMalformedIDs(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	if resp := f.do("GET", "/api/scans/20260101T000000.000000000Z-deadbeef", "", cookie); resp.StatusCode != 404 {
		t.Errorf("absent id: %d, want 404", resp.StatusCode)
	}
	for _, id := range []string{"..", "x", "%2e%2e%2fsecret", "20260101T000000.000000000Z-DEADBEEF"} {
		if resp := f.do("GET", "/api/scans/"+id, "", cookie); resp.StatusCode != 400 && resp.StatusCode != 404 && resp.StatusCode != 307 {
			// The mux canonicalises ".." and answers 307 before any handler runs.
			t.Errorf("id %q: %d, want 400, 404 or the mux's 307", id, resp.StatusCode)
		}
	}
}

// A 500 must not leak the filesystem path the error mentions.
func TestScan_InternalErrorsDoNotLeakPaths(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	id := f.addScan(history.Input{Command: "attribute", Image: "x"})
	if err := os.WriteFile(filepath.Join(f.store.Dir(), id+".json"), []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := f.do("GET", "/api/scans/"+id, "", cookie)
	body := readBody(t, resp)
	if resp.StatusCode != 500 || strings.Contains(body, f.store.Dir()) || strings.Contains(body, ".json") {
		t.Errorf("status %d body %q: want a 500 that names no path", resp.StatusCode, body)
	}
}

func TestPinsLatest_OnePerDockerfileNewestWins(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	f.store = mustSetClock(t, f.store, time.Now().Add(-2*time.Hour))
	f.srv.store = f.store
	f.addScan(history.Input{Command: "pins-check", Dockerfile: "a/Dockerfile", Pins: []pins.Pin{{Package: "old", Status: pins.StatusCurrent}}})
	f.store = mustSetClock(t, f.store, time.Now().Add(-1*time.Hour))
	f.srv.store = f.store
	f.addScan(history.Input{Command: "pins-check", Dockerfile: "a/Dockerfile", Pins: []pins.Pin{{Package: "curl", Status: pins.StatusUpdateAvailable}}})
	f.addScan(history.Input{Command: "pins-check", Dockerfile: "b/Dockerfile", Pins: []pins.Pin{{Package: "wget", Status: pins.StatusCurrent}}})
	f.addScan(history.Input{Command: "attribute", Image: "ignored"}) // not a pins record

	var out struct {
		Records []history.Record `json:"records"`
	}
	getJSON(t, f, "/api/pins/latest", cookie, &out)
	if len(out.Records) != 2 {
		t.Fatalf("got %d records, want one per Dockerfile (2)", len(out.Records))
	}
	got := map[string]string{}
	for _, r := range out.Records {
		got[r.Summary.Dockerfile] = r.Pins[0].Package
	}
	if got["a/Dockerfile"] != "curl" || got["b/Dockerfile"] != "wget" {
		t.Errorf("latest per dockerfile = %v", got)
	}
}

func TestUnknownAPIPathIsJSON404(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	var e apiError
	resp := getJSON(t, f, "/api/nope", cookie, &e)
	if resp.StatusCode != 404 || e.Error == "" {
		t.Errorf("status %d body %+v", resp.StatusCode, e)
	}
}

// ── static assets ────────────────────────────────────────────────────────────

func TestStatic_ServesIndexAndNoDirectoryListings(t *testing.T) {
	f := newFixture(t)
	cookie := f.login()
	resp := f.do("GET", "/", "", cookie)
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("/: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	for _, p := range []string{"/assets/", "/assets", "/../go.mod", "/%2e%2e/go.mod", "/nope.js"} {
		if resp := f.do("GET", p, "", cookie); resp.StatusCode == 200 {
			body := readBody(t, resp)
			if p != "/assets/" && p != "/assets" || strings.Contains(body, "<a href") {
				t.Errorf("GET %s: 200 with %.60q", p, body)
			}
		}
	}
}

func TestRepository(t *testing.T) {
	for in, want := range map[string]string{
		"app":                          "app",
		"app:1.2":                      "app",
		"reg.io/team/app:latest":       "reg.io/team/app",
		"reg.io:5000/app":              "reg.io:5000/app",
		"reg.io:5000/app:3":            "reg.io:5000/app",
		"reg.io/app@sha256:abc":        "reg.io/app",
		"reg.io:5000/app:3@sha256:abc": "reg.io:5000/app",
		"":                             "",
	} {
		if got := Repository(in); got != want {
			t.Errorf("Repository(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestListen_BindsLoopbackOnly(t *testing.T) {
	store, _ := history.Open(filepath.Join(t.TempDir(), "h"))
	srv, _ := New(store)
	ln, err := srv.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if host, _, _ := strings.Cut(ln.Addr().String(), ":"); host != "127.0.0.1" {
		t.Errorf("listening on %s, want 127.0.0.1 only", ln.Addr())
	}
	if !strings.HasPrefix(srv.LaunchURL(), "http://127.0.0.1:") || !strings.Contains(srv.LaunchURL(), "?token=") {
		t.Errorf("LaunchURL = %q", srv.LaunchURL())
	}
	if _, err := srv.Listen(70000); err == nil {
		t.Error("an out-of-range port must be rejected")
	}
}

func TestOpenBrowser_RefusesNonLoopbackURLs(t *testing.T) {
	for _, u := range []string{"https://evil.example/", "http://evil.example/", "file:///etc/passwd", "http://localhost:1/", "javascript:alert(1)", ""} {
		if err := OpenBrowser(u); err == nil {
			t.Errorf("OpenBrowser(%q) must refuse", u)
		}
	}
}

// mustSetClock returns a store over the same directory whose clock is fixed,
// so records get controllable timestamps.
func mustSetClock(t *testing.T, s *history.Store, now time.Time) *history.Store {
	t.Helper()
	return s.WithClock(func() time.Time { return now })
}
