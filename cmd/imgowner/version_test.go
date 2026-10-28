package main

import (
	"runtime/debug"
	"testing"
)

// The acceptance run found `go install github.com/.../imgowner@v0.5.0`
// reporting `imgowner dev (commit none, built unknown)`: go install never
// runs -ldflags, so the version/commit/date vars kept their zero values.
func TestVersionFromBuildInfo(t *testing.T) {
	for name, c := range map[string]struct {
		bi                                *debug.BuildInfo
		wantVersion, wantCommit, wantDate string
	}{
		"a real module version, v-prefixed": {
			bi: &debug.BuildInfo{
				Main: debug.Module{Version: "v0.6.0"},
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "abc123"},
					{Key: "vcs.time", Value: "2026-10-28T00:00:00Z"},
				},
			},
			wantVersion: "0.6.0", wantCommit: "abc123", wantDate: "2026-10-28T00:00:00Z",
		},
		"go install pins a pseudo-version too": {
			bi:          &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261028000000-abcdef123456"}},
			wantVersion: "0.0.0-20261028000000-abcdef123456",
		},
		"a plain `go build` inside the module reports (devel)": {
			bi: &debug.BuildInfo{
				Main:     debug.Module{Version: "(devel)"},
				Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "deadbee"}},
			},
			wantVersion: "", wantCommit: "deadbee", // no release version, but still a commit
		},
		"no settings at all": {
			bi: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
		},
		"irrelevant settings are ignored": {
			bi: &debug.BuildInfo{
				Main: debug.Module{Version: "(devel)"},
				Settings: []debug.BuildSetting{
					{Key: "GOOS", Value: "linux"},
					{Key: "vcs.modified", Value: "true"},
				},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			v, co, d := versionFromBuildInfo(c.bi)
			if v != c.wantVersion || co != c.wantCommit || d != c.wantDate {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)", v, co, d, c.wantVersion, c.wantCommit, c.wantDate)
			}
		})
	}
}

// A release build's -ldflags-set version must never be overwritten by
// whatever go install/build-info happens to say (e.g. the goreleaser build
// step itself runs as a plain `go build`, which would otherwise report
// "(devel)" and leave a real release with no version string undone — no,
// worse, silently keep the correct ldflags value only because version != "dev"
// short-circuits fillVersionFromBuildInfo before it ever runs).
func TestFillVersionFromBuildInfo_LdflagsVersionIsNeverOverwritten(t *testing.T) {
	old := version
	defer func() { version = old }()
	version = "0.6.0"
	fillVersionFromBuildInfo()
	if version != "0.6.0" {
		t.Errorf("version changed to %q, want it left at the ldflags value", version)
	}
}
