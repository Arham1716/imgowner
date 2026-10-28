package pins

import "testing"

func TestVersionAtLeast(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"7.88.1-10+deb12u15", "7.88.1-10+deb12u8", true},
		{"7.88.1-10+deb12u5", "7.88.1-10+deb12u8", false},
		{"1.0", "1.0~rc1", true},
		{"1.0~rc1", "1.0", false},
		{"8.14.1-r2", "8.14.1-r1", true},
		{"1.34-13.el9_8", "1.34-11.el9", true},
		{"1:2.39.2-1", "2.40.0-1", true}, // epoch wins
		{"2.10", "2.9", true},            // numeric, not lexical
		{"1.2.3", "1.2.3", true},
	} {
		if got := VersionAtLeast(c.a, c.b); got != c.want {
			t.Errorf("VersionAtLeast(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
