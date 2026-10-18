package baserec

import "testing"

func TestFilterCandidates(t *testing.T) {
	allTags := []string{
		"3.12-slim",        // current — excluded
		"3.12.0-slim",      // equal to 3.12 (same semver) — excluded
		"3.12.1-slim",      // patch bump — candidate
		"3.13-slim",        // minor bump, same suffix — candidate
		"3.12-bookworm",    // different suffix — excluded
		"3.11-slim",        // older minor — excluded
		"latest",           // no suffix match — excluded
	}

	got := filterCandidates("3.12-slim", allTags)

	want := map[string]bool{
		"3.12.1-slim": true,
		"3.13-slim":   true,
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d candidates, got %d: %v", len(want), len(got), got)
	}

	for _, tag := range got {
		if !want[tag] {
			t.Errorf("unexpected candidate: %s", tag)
		}
	}
}

func TestSplitTagVariant(t *testing.T) {
	cases := []struct{ tag, ver, suffix string }{
		{"3.12-slim", "3.12", "slim"},
		{"1.25-alpine", "1.25", "alpine"},
		{"3.12.1-slim", "3.12.1", "slim"},
		{"latest", "latest", ""},
		{"20-bookworm", "20", "bookworm"},
	}
	for _, tc := range cases {
		v, s := splitTagVariant(tc.tag)
		if v != tc.ver || s != tc.suffix {
			t.Errorf("splitTagVariant(%q): want (%q,%q) got (%q,%q)", tc.tag, tc.ver, tc.suffix, v, s)
		}
	}
}

func TestSemverGt(t *testing.T) {
	cases := []struct {
		a, b [3]int
		want bool
	}{
		{[3]int{3, 13, 0}, [3]int{3, 12, 0}, true},
		{[3]int{3, 12, 1}, [3]int{3, 12, 0}, true},
		{[3]int{3, 12, 0}, [3]int{3, 12, 0}, false},
		{[3]int{3, 11, 0}, [3]int{3, 12, 0}, false},
	}
	for _, tc := range cases {
		if got := semverGt(tc.a, tc.b); got != tc.want {
			t.Errorf("semverGt(%v, %v): want %v got %v", tc.a, tc.b, tc.want, got)
		}
	}
}

func TestSortCandidates(t *testing.T) {
	cs := []Candidate{
		{Tag: "3.12.1-slim", CVEsRemoved: 10, Failed: false},
		{Tag: "3.13-slim", CVEsRemoved: 50, Failed: false},
		{Tag: "3.12.2-slim", Failed: true},
	}
	sortCandidates(cs)

	if cs[0].Tag != "3.13-slim" {
		t.Errorf("first candidate should be 3.13-slim (most CVEs removed), got %s", cs[0].Tag)
	}
	if cs[2].Tag != "3.12.2-slim" || !cs[2].Failed {
		t.Errorf("last candidate should be the failed one, got %s failed=%v", cs[2].Tag, cs[2].Failed)
	}
}
