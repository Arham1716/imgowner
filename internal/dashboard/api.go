package dashboard

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Arham1716/imgowner/internal/history"
)

const (
	defaultScanLimit = 2000
	maxScanLimit     = 5000
	maxRepoParam     = 512
	maxDaysParam     = 3650
)

// scanQuery is the validated form of /api/scans' query string.
type scanQuery struct {
	Repo  string
	Limit int
	Days  int // 0 = no time bound
}

// paramError names the query parameter that was rejected.
type paramError struct {
	Param string
	Msg   string
}

func (e *paramError) Error() string { return e.Param + ": " + e.Msg }

// parseScanQuery validates the query parameters of the scan listing (NFR-13):
// bounded lengths and ranges, no surprises. It is fuzzed (FR-46).
func parseScanQuery(v url.Values) (scanQuery, *paramError) {
	q := scanQuery{Limit: defaultScanLimit}

	if repo := v.Get("repo"); repo != "" {
		if len(repo) > maxRepoParam || !utf8.ValidString(repo) || strings.ContainsAny(repo, "\x00\r\n") {
			return q, &paramError{"repo", "must be a valid string of at most 512 bytes"}
		}
		q.Repo = repo
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxScanLimit {
			return q, &paramError{"limit", "must be an integer from 1 to 5000"}
		}
		q.Limit = n
	}
	if s := v.Get("days"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxDaysParam {
			return q, &paramError{"days", "must be an integer from 1 to 3650"}
		}
		q.Days = n
	}
	return q, nil
}

// Repository strips the tag and digest from an image reference, so every scan
// of the same image groups together on the Overview.
func Repository(image string) string {
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		image = image[:i]
	}
	return image
}

// scanItem is a listed scan: its summary plus the repository it groups under.
type scanItem struct {
	history.Summary
	Repository string `json:"repository"`
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	q, perr := parseScanQuery(r.URL.Query())
	if perr != nil {
		writeError(w, http.StatusBadRequest, perr.Msg, perr.Param)
		return
	}
	sums, skipped, err := s.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read scan history", "")
		return
	}
	var cutoff time.Time
	if q.Days > 0 {
		cutoff = time.Now().UTC().Add(-time.Duration(q.Days) * 24 * time.Hour)
	}
	items := make([]scanItem, 0, min(len(sums), q.Limit))
	for _, sum := range sums { // newest first
		if len(items) >= q.Limit {
			break
		}
		if !cutoff.IsZero() && sum.Timestamp.Before(cutoff) {
			continue
		}
		repo := Repository(sum.Image)
		if q.Repo != "" && repo != q.Repo {
			continue
		}
		items = append(items, scanItem{Summary: sum, Repository: repo})
	}
	writeJSON(w, http.StatusOK, struct {
		Scans   []scanItem `json:"scans"`
		Skipped int        `json:"skipped"`
	}{items, skipped})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	rec, err := s.store.Get(r.PathValue("id"))
	switch {
	case errors.Is(err, history.ErrInvalidID):
		writeError(w, http.StatusBadRequest, "invalid scan id", "id")
	case errors.Is(err, history.ErrNotFound):
		writeError(w, http.StatusNotFound, "scan not found", "id")
	case err != nil:
		// The underlying error can name a file path; the browser gets neither.
		writeError(w, http.StatusInternalServerError, "could not read scan", "")
	default:
		writeJSON(w, http.StatusOK, rec)
	}
}

// handlePinsLatest returns the most recent pins-check record for each
// Dockerfile that has one.
func (s *Server) handlePinsLatest(w http.ResponseWriter, r *http.Request) {
	sums, _, err := s.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read scan history", "")
		return
	}
	seen := map[string]bool{}
	out := make([]*history.Record, 0, 4)
	for _, sum := range sums { // newest first
		if sum.Command != "pins-check" || seen[sum.Dockerfile] {
			continue
		}
		seen[sum.Dockerfile] = true
		rec, err := s.store.Get(sum.ID)
		if err != nil {
			continue // one unreadable record shouldn't hide the others
		}
		out = append(out, rec)
	}
	writeJSON(w, http.StatusOK, struct {
		Records []*history.Record `json:"records"`
	}{out})
}
