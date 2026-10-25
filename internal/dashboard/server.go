// Package dashboard is the local, read-only web dashboard (FR-33..FR-38). It
// serves the embedded single-page app and a small JSON API over the scan
// history store, bound to 127.0.0.1 only.
//
// Threat model: the listener is reachable by every process on the machine and
// by any web page the user has open (DNS rebinding, cross-site requests). So,
// beyond binding to loopback, every request must (1) carry a loopback Host
// header, (2) be a GET/HEAD, and (3) present a session cookie that the browser
// only obtains by redeeming a one-time launch token printed at startup
// (NFR-10). The page can load nothing from outside the machine (CSP).
package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Arham1716/imgowner/internal/history"
)

// The compiled frontend (web/dashboard) is committed here so `go install`
// users get the dashboard without needing Node; CI rebuilds it from source
// and fails on any byte of difference.
//
//go:embed all:dist
var distFS embed.FS

const (
	sessionCookie = "imgowner_session"
	tokenQuery    = "token"
)

// csp allows nothing from outside the machine: no remote scripts, styles,
// fonts, images or connections, no framing, no forms, no <base>.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// Server serves the dashboard. Create it with New; it holds no state besides
// its tokens, so it is safe for concurrent requests.
type Server struct {
	store        *history.Store
	assets       fs.FS
	files        map[string]string // embedded file allowlist: name -> name, built once
	launchToken  string
	sessionToken string
	launchUsed   atomic.Bool
	addr         atomic.Value // string: the listener's host:port
}

// New returns a Server over store with freshly generated random tokens.
func New(store *history.Store) (*Server, error) {
	assets, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, fmt.Errorf("dashboard: embedded assets: %w", err)
	}
	files := map[string]string{}
	err = fs.WalkDir(assets, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files[p] = p
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("dashboard: indexing embedded assets: %w", err)
	}
	launch, err := randomToken()
	if err != nil {
		return nil, err
	}
	session, err := randomToken()
	if err != nil {
		return nil, err
	}
	return &Server{store: store, assets: assets, files: files, launchToken: launch, sessionToken: session}, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("dashboard: generating token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Listen binds 127.0.0.1 only. port 0 picks a free port.
func (s *Server) Listen(port int) (net.Listener, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("dashboard: invalid port %d", port)
	}
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("dashboard: listening on 127.0.0.1:%d: %w", port, err)
	}
	s.setAddr(ln.Addr().String())
	return ln, nil
}

func (s *Server) setAddr(a string) { s.addr.Store(a) }

func (s *Server) listenAddr() string {
	a, _ := s.addr.Load().(string)
	return a
}

// LaunchURL is the URL to open: it carries the one-time launch token.
func (s *Server) LaunchURL() string {
	return "http://" + s.listenAddr() + "/?" + tokenQuery + "=" + url.QueryEscape(s.launchToken)
}

// Serve runs until ctx is cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	// Read every record's summary now, in the background, so the first page
	// load finds a warm cache instead of paying for the whole history.
	go func() { _, _, _ = s.store.List() }()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("dashboard: shutting down: %w", err)
		}
		return nil
	}
}

// Handler returns the full request pipeline.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/scans", s.handleScans)
	mux.HandleFunc("GET /api/scans/{id}", s.handleScan)
	mux.HandleFunc("GET /api/pins/latest", s.handlePinsLatest)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found", "")
	})
	mux.HandleFunc("/", s.handleStatic)

	// Outermost first: headers, then Host, then method, then auth.
	return s.securityHeaders(s.hostCheck(methodCheck(s.auth(mux))))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// hostCheck defeats DNS rebinding: a page on attacker.example that rebinds its
// name to 127.0.0.1 still sends "Host: attacker.example:port", which is
// refused here. It also rejects an explicitly cross-site fetch.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			writeError(w, http.StatusForbidden, "invalid host", "")
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			writeError(w, http.StatusForbidden, "cross-site request refused", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(host string) bool {
	addr := s.listenAddr()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	h := strings.ToLower(host)
	return h == "127.0.0.1:"+port || h == "localhost:"+port
}

// methodCheck makes the server read-only (FR-38): nothing but GET and HEAD
// ever reaches a handler, whatever the path.
func methodCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, http.StatusMethodNotAllowed, "read-only dashboard: only GET is allowed", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// auth redeems the one-time launch token for a session cookie, and otherwise
// requires that cookie. The launch token is burned on first use, so a copy
// read off the process list by another local user is useless once the
// legitimate browser has opened the page.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok := r.URL.Query().Get(tokenQuery); tok != "" {
			if !tokenEqual(tok, s.launchToken) || !s.launchUsed.CompareAndSwap(false, true) {
				writeError(w, http.StatusUnauthorized, "invalid or already used launch token", "")
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookie,
				Value:    s.sessionToken,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				// No Secure flag: the server is plain HTTP on loopback, and a
				// Secure cookie would not be sent back by every browser there.
			})
			q := r.URL.Query()
			q.Del(tokenQuery)
			dest := r.URL.Path
			if len(q) > 0 {
				dest += "?" + q.Encode()
			}
			http.Redirect(w, r, dest, http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil || !tokenEqual(c.Value, s.sessionToken) {
			writeError(w, http.StatusUnauthorized, "missing or invalid session; open the URL printed by `imgowner dashboard`", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func tokenEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	// Only a name that is a key of the allowlist built from the embedded files
	// is ever served, and what reaches the file API is the allowlist's own
	// string, never the request's: no request data can name a path.
	file, ok := s.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	http.ServeFileFS(w, r, s.assets, file)
}

// ── JSON helpers ─────────────────────────────────────────────────────────────

type apiError struct {
	Error string `json:"error"`
	Param string `json:"param,omitempty"`
}

func writeError(w http.ResponseWriter, status int, msg, param string) {
	writeJSON(w, status, apiError{Error: msg, Param: param})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
