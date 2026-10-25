package dashboard

import (
	"fmt"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/history"
	"github.com/Arham1716/imgowner/internal/pins"
)

// NFR-17: every view must render within 2 seconds on a history of 90 days at
// 50 scans a day (4,500 records). The page itself is a few hundred
// kilobytes of static JavaScript, so the part that scales with history is the
// API the views call; each of those must answer well inside half that budget
// (the other half is the browser's, which gets the full 4,500 summaries in a
// single response).
func TestPerformance_NinetyDaysAtFiftyScansPerDay(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds 4,500 records; skipped under -short")
	}
	const (
		days    = 90
		perDay  = 50
		budget  = time.Second
		repeats = 3
	)
	f := newFixture(t)
	cookie := f.login()

	now := time.Now().UTC()
	var newestID string
	for i := 0; i < days*perDay; i++ {
		at := now.Add(-time.Duration(i) * (24 * time.Hour / perDay))
		s := f.store.WithClock(func() time.Time { return at })
		findings := make([]attribution.Finding, 40) // a typical small image
		for j := range findings {
			findings[j] = attribution.Finding{
				CVE: fmt.Sprintf("CVE-2025-%04d", j), Severity: "HIGH", Package: "pkg" + fmt.Sprint(j%9),
				InstalledVersion: "1.2.3-r1", FixedVersion: "1.3.0-r2", Owner: attribution.OwnerBase, Confidence: "exact",
				Instruction: &attribution.DockerfileRef{Line: 7, Text: "RUN apt-get install -y --no-install-recommends curl"},
			}
		}
		id, err := s.Append(history.NewRecord(history.Input{
			Command: "attribute", Image: fmt.Sprintf("registry.local/app-%d:%d", i%5, i), Digest: "sha256:abc", Findings: findings,
		}))
		if err != nil {
			t.Fatalf("seeding record %d: %v", i, err)
		}
		if newestID == "" || id > newestID {
			newestID = id
		}
	}
	if _, err := f.store.WithClock(func() time.Time { return now }).Append(history.NewRecord(history.Input{
		Command: "pins-check", Dockerfile: "Dockerfile", Pins: []pins.Pin{{Package: "curl", Status: pins.StatusCurrent}},
	})); err != nil {
		t.Fatal(err)
	}

	get := func(path string) time.Duration {
		start := time.Now()
		resp := f.do("GET", path, "", cookie)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d", path, resp.StatusCode)
		}
		_ = readBody(t, resp)
		return time.Since(start)
	}

	for _, p := range []string{
		"/api/scans?days=90&limit=5000", // what the dashboard loads on every visit
		"/api/scans/" + newestID,        // the Findings / Base images / Overview detail
		"/api/pins/latest",              // the Pins view
	} {
		// The first request after startup reads every record (the server also
		// pre-warms this in the background); it alone must fit the whole 2s
		// NFR-17 budget. Every later request is served from the cache.
		cold := get(p)
		var warm []time.Duration
		for i := 0; i < repeats; i++ {
			warm = append(warm, get(p))
		}
		sort.Slice(warm, func(i, j int) bool { return warm[i] < warm[j] })
		t.Logf("GET %-40s cold %v, warm median %v", p, cold, warm[len(warm)/2])
		if cold > 2*time.Second {
			t.Errorf("GET %s: cold %v at 4,500 records exceeds the 2s budget (NFR-17)", p, cold)
		}
		if warm[len(warm)/2] > budget/2 {
			t.Errorf("GET %s: warm median %v exceeds %v", p, warm[len(warm)/2], budget/2)
		}
	}
}
