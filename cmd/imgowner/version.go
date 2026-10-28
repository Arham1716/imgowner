package main

import (
	"runtime/debug"
	"strings"
)

// fillVersionFromBuildInfo covers `go install github.com/.../imgowner@vX.Y.Z`,
// which the README documents as a supported install path but which has no
// -ldflags step: version/commit/date stayed "dev"/"none"/"unknown" even for a
// pinned release, which `imgowner --version` could never tell apart from a
// one-off local build.
//
// Go embeds the module version and VCS info into every binary it builds from
// a module (readable back via debug.ReadBuildInfo), so this fills version,
// commit and date from that when -ldflags didn't already set them.
func fillVersionFromBuildInfo() {
	if version != "dev" {
		return // -ldflags already set a real version (a goreleaser release build)
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	v, c, d := versionFromBuildInfo(bi)
	if v != "" {
		version = v
	}
	if c != "" {
		commit = c
	}
	if d != "" {
		date = d
	}
}

// versionFromBuildInfo is the pure part of fillVersionFromBuildInfo, so it
// can be tested without depending on how this particular test binary itself
// was built. It returns "" for any field build info doesn't answer.
//
// A plain `go build` inside this repo (not `go install pkg@version`) reports
// Main.Version as "(devel)": there is no release version to report, so
// version comes back "" (the caller leaves it at "dev"), but commit/date are
// still filled in from VCS settings when available.
func versionFromBuildInfo(bi *debug.BuildInfo) (version, commit, date string) {
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		version = strings.TrimPrefix(v, "v")
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			commit = s.Value
		case "vcs.time":
			date = s.Value
		}
	}
	return version, commit, date
}
