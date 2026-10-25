package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/config"
	"github.com/Arham1716/imgowner/internal/pins"
)

func TestCVEFixesFor(t *testing.T) {
	pinList := []pins.Pin{
		{Package: "curl", Version: "7.88.1-10+deb12u5", Available: "7.88.1-10+deb12u15", Status: pins.StatusUpdateAvailable},
		{Package: "git", Version: "1:2.39.2-1", Available: "1:2.39.2-1.1", Status: pins.StatusUpdateAvailable},
	}
	findings := []attribution.Finding{
		{CVE: "CVE-A", Package: "curl", InstalledVersion: "7.88.1-10+deb12u5", FixedVersion: "7.88.1-10+deb12u8"},        // reached
		{CVE: "CVE-B", Package: "curl", InstalledVersion: "7.88.1-10+deb12u5", FixedVersion: "8.0.0"},                    // not reached
		{CVE: "CVE-C", Package: "curl", InstalledVersion: "7.88.1-10+deb12u5", FixedVersion: ""},                         // no fix yet
		{CVE: "CVE-D", Package: "curl", InstalledVersion: "7.0.0", FixedVersion: "7.88.1-10+deb12u8"},                    // other version
		{CVE: "CVE-A", Package: "curl", InstalledVersion: "7.88.1-10+deb12u5", FixedVersion: "7.88.1-10+deb12u8"},        // duplicate
		{CVE: "CVE-E", Package: "git", InstalledVersion: "1:2.39.2-1", FixedVersion: "1:2.39.5-0+deb12u1, 1:2.39.2-1.1"}, // one of a list
	}
	got := cveFixesFor(pinList, findings)
	want := map[string][]string{"curl": {"CVE-A"}, "git": {"CVE-E"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if out := pins.ApplyCVEFixes(pinList, got); out[0].Status != pins.StatusFixesCVEs || out[1].Status != pins.StatusFixesCVEs {
		t.Errorf("statuses not promoted: %+v", out)
	}
}

// FR-27: no container runtime means the pin check is skipped *with a note*,
// never silently and never as a failure.
func TestCIPins_NoRuntimeIsReportedNotFatal(t *testing.T) {
	dir := t.TempDir()
	df := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(df, []byte("FROM debian:12\nRUN apt-get install -y curl=7.88.1-10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir) // no docker, no podman
	pinList, note := ciPins(context.Background(), config.Defaults(), df, nil)
	if len(pinList) != 1 || !strings.Contains(note, "no container runtime") {
		t.Fatalf("got %d pins, note %q", len(pinList), note)
	}
}

func TestCIPins_DisabledDoesNothing(t *testing.T) {
	cfg := config.Defaults()
	cfg.Pins.Enabled = false
	if p, note := ciPins(context.Background(), cfg, "does-not-matter", nil); p != nil || note != "" {
		t.Fatalf("pins.enabled=false still ran: %v %q", p, note)
	}
}
