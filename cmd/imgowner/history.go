package main

import (
	"fmt"
	"os"

	"github.com/Arham1716/imgowner/internal/config"
	"github.com/Arham1716/imgowner/internal/history"
)

// recordHistory appends a finished scan to the local history store and prunes
// records past the retention window (FR-31, FR-32). It runs only after a run
// has already succeeded (exit 0 or 1), and a failure here is only a warning on
// stderr: history is a convenience, so a read-only home directory or a full
// disk must never turn a passing scan into a failing one -- and stdout stays
// clean for --format json.
func recordHistory(cfg config.Config, in history.Input) {
	if !cfg.History.Enabled {
		return
	}
	store, err := history.Open(cfg.History.Dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: scan history not recorded: %v\n", err)
		return
	}
	if _, err := store.Append(history.NewRecord(in)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: scan history not recorded: %v\n", err)
		return
	}
	if _, err := store.Prune(cfg.History.RetentionDays); err != nil {
		fmt.Fprintf(os.Stderr, "warning: scan history pruning incomplete: %v\n", err)
	}
}
