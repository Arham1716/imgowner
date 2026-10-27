package main

import (
	"strings"
	"testing"

	"github.com/Arham1716/imgowner/internal/config"
	"github.com/Arham1716/imgowner/internal/report"
)

func TestReportTarget(t *testing.T) {
	cfg := config.Defaults() // formats md,json; output_dir ./imgowner-report
	for _, c := range []struct {
		name           string
		formats        []string
		dir            string
		singleToStdout bool
		wantFormats    string
		wantDir        string
		wantErr        bool
	}{
		// attribute: one --format keeps printing to stdout (scripts, the VS Code extension).
		{"attribute single format", []string{"json"}, "", true, "json", report.Stdout, false},
		// attribute: the md+json default no longer shares stdout.
		{"attribute default", nil, "", true, "md,json", cfg.Report.OutputDir, false},
		{"attribute comma list", []string{"md,json,sarif"}, "", true, "md,json,sarif", cfg.Report.OutputDir, false},
		{"attribute explicit dir", []string{"json"}, "out", true, "json", "out", false},
		// ci: always files unless told otherwise.
		{"ci single format", []string{"json"}, "", false, "json", cfg.Report.OutputDir, false},
		{"ci forced stdout", []string{"sarif"}, report.Stdout, false, "sarif", report.Stdout, false},
		{"stdout with two formats", []string{"md", "json"}, report.Stdout, false, "", "", true},
		{"unknown format", []string{"xml"}, "", true, "", "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			fmts, dir, err := reportTarget(c.formats, c.dir, cfg, c.singleToStdout)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if c.wantErr {
				return
			}
			if strings.Join(fmts, ",") != c.wantFormats || dir != c.wantDir {
				t.Errorf("got %v -> %q, want %s -> %q", fmts, dir, c.wantFormats, c.wantDir)
			}
		})
	}
}
