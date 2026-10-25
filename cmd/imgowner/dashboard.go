package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Arham1716/imgowner/internal/dashboard"
	"github.com/Arham1716/imgowner/internal/history"
)

// dashboardCmd serves the local, read-only dashboard over the scan history
// (FR-33). It deliberately does not go through loadConfig: that also demands a
// working Trivy, and browsing past scans needs none.
func dashboardCmd(ctx context.Context, cfgPath *string) *cobra.Command {
	var (
		noOpen bool
		port   int
	)
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Open the local dashboard over your scan history",
		Long: "Starts a read-only web dashboard on 127.0.0.1 (this machine only) over the scan\n" +
			"history that attribute, ci and pins check record, and opens it in your browser.\n" +
			"The printed URL carries a one-time token; reloading the page keeps working, but\n" +
			"to open it in a different browser, stop and restart this command.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := readConfig(*cfgPath)
			if err != nil {
				return writeStructuredError(structuredScanErr(err))
			}
			store, err := history.Open(cfg.History.Dir)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			srv, err := dashboard.New(store)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			ln, err := srv.Listen(port)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			defer func() { _ = ln.Close() }()

			url := srv.LaunchURL()
			fmt.Printf("imgowner dashboard: %s\n", url)
			fmt.Println("Press Ctrl+C to stop.")
			if !noOpen {
				if err := dashboard.OpenBrowser(url); err != nil {
					fmt.Fprintf(os.Stderr, "warning: could not open a browser (%v); use the URL above\n", err)
				}
			}
			if err := srv.Serve(ctx, ln); err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			return nil // Ctrl+C is a normal stop: exit 0
		},
	}
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "print the URL but don't open a browser")
	cmd.Flags().IntVar(&port, "port", 0, "port to listen on (default: a free port)")
	return cmd
}
