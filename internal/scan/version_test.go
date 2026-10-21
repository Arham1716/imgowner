package scan

import "testing"

func TestParseSemver(t *testing.T) {
	cases := []struct {
		in   string
		want [3]int
	}{
		{"0.76.0", [3]int{0, 76, 0}},
		{"v0.76.0", [3]int{0, 76, 0}}, // leading "v" is stripped
		{"1.2", [3]int{1, 2, 0}},      // missing patch defaults to 0
		{"1", [3]int{1, 0, 0}},
		{"", [3]int{0, 0, 0}},
	}
	for _, tc := range cases {
		if got := parseSemver(tc.in); got != tc.want {
			t.Errorf("parseSemver(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		found, required string
		want            bool
	}{
		{"0.76.0", "0.76.0", true},  // exact match satisfies the floor
		{"0.77.0", "0.76.0", true},  // newer minor
		{"0.76.1", "0.76.0", true},  // newer patch
		{"0.75.9", "0.76.0", false}, // older minor, despite higher patch
		{"1.0.0", "0.76.0", true},   // newer major
		{"v0.76.0", "0.76.0", true}, // "v" prefix from `trivy version` output
	}
	for _, tc := range cases {
		if got := versionAtLeast(tc.found, tc.required); got != tc.want {
			t.Errorf("versionAtLeast(%q, %q) = %v, want %v", tc.found, tc.required, got, tc.want)
		}
	}
}
