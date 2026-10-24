package dashboard

import (
	"net/url"
	"testing"
)

// FuzzParseScanQuery throws arbitrary query strings at the parameter
// validator (FR-46): it must never panic, and whatever it accepts must be
// within the documented bounds.
func FuzzParseScanQuery(f *testing.F) {
	for _, s := range []string{
		"", "limit=10", "days=30&repo=reg.local/app", "limit=0", "limit=-1&days=x",
		"repo=%00", "repo=a%0Ab", "limit=99999999999999999999", "days=1&days=2",
		"%zz", "repo=" + string(make([]byte, 600)),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		v, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		q, perr := parseScanQuery(v)
		if perr != nil {
			if perr.Param == "" || perr.Msg == "" {
				t.Fatalf("a rejection must name its parameter and reason: %+v", perr)
			}
			return
		}
		if q.Limit < 1 || q.Limit > maxScanLimit || q.Days < 0 || q.Days > maxDaysParam || len(q.Repo) > maxRepoParam {
			t.Fatalf("accepted an out-of-bounds query: %+v", q)
		}
	})
}

// FuzzRepository: grouping must never panic on any image string.
func FuzzRepository(f *testing.F) {
	for _, s := range []string{"", "a", "a:b", "a@b", "a:b@c", "h:1/a:b", ":", "@", "::@@", "/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if r := Repository(s); len(r) > len(s) {
			t.Fatalf("Repository(%q) = %q is longer than its input", s, r)
		}
	})
}
