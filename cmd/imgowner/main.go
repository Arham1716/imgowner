package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/Arham1716/imgowner/internal/config"
	"github.com/Arham1716/imgowner/internal/scan"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := rootCmd(ctx).ExecuteContext(ctx); err != nil {
		os.Exit(2)
	}
}

func rootCmd(ctx context.Context) *cobra.Command {
	var cfgPath string

	root := &cobra.Command{
		Use:           "imgowner",
		Short:         "Container CVE attribution and OS package pin updater",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&cfgPath, "config", ".imgowner.yaml", "config file path")

	root.AddCommand(
		attributeCmd(ctx, &cfgPath),
		pinsCmd(ctx, &cfgPath),
		ciCmd(ctx, &cfgPath),
	)
	return root
}

// loadConfig reads and validates the config file, then checks Trivy version.
// Returns the config and the resolved Trivy version string.
func loadConfig(ctx context.Context, cfgPath string) (config.Config, string, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return config.Config{}, "", err
	}

	if err := scan.CheckTrivyVersion(ctx, cfg.Scan.TrivyMinVersion); err != nil {
		return config.Config{}, "", err
	}

	// Re-read the Trivy version for cache keying.
	trivyVer, err := scan.InstalledVersion(ctx)
	if err != nil {
		return config.Config{}, "", err
	}

	return cfg, trivyVer, nil
}

// writeStructuredError writes a JSON error to stderr and returns a generic error
// so cobra can exit cleanly without printing the raw message.
func writeStructuredError(payload any) error {
	_ = json.NewEncoder(os.Stderr).Encode(payload)
	return fmt.Errorf("") // cobra prints this if non-empty; keep blank
}

// ── attribute ────────────────────────────────────────────────────────────────

func attributeCmd(ctx context.Context, cfgPath *string) *cobra.Command {
	var (
		imageRef     string
		dockerfilePath string
		baseDigest   string
		formats      []string
		baseCandidates int
	)

	cmd := &cobra.Command{
		Use:   "attribute",
		Short: "Attribute CVEs to base image, added OS packages, or app libraries",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// FR-01: validate --dockerfile early (F10 gate)
			if dockerfilePath == "" {
				return writeStructuredError(map[string]string{
					"error": "dockerfile not found",
					"path":  dockerfilePath,
					"hint":  "pass --dockerfile <path>",
				})
			}
			if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
				return writeStructuredError(map[string]string{
					"error": "dockerfile not found",
					"path":  dockerfilePath,
				})
			}
			if imageRef == "" {
				return writeStructuredError(map[string]string{
					"error": "image reference required",
					"hint":  "pass --image <ref>",
				})
			}

			cfg, trivyVer, err := loadConfig(ctx, *cfgPath)
			if err != nil {
				return writeStructuredError(structuredScanErr(err))
			}
			_ = trivyVer
			_ = cfg
			_ = baseDigest
			_ = formats
			_ = baseCandidates

			// TODO M1: wire attribution pipeline
			fmt.Fprintln(os.Stderr, "attribute: not yet implemented")
			return nil
		},
	}

	cmd.Flags().StringVar(&imageRef, "image", "", "image reference to scan (required)")
	cmd.Flags().StringVar(&dockerfilePath, "dockerfile", "Dockerfile", "path to Dockerfile")
	cmd.Flags().StringVar(&baseDigest, "base-digest", "", "override base image digest")
	cmd.Flags().StringArrayVar(&formats, "format", []string{"md", "json"}, "output formats (md,json,sarif)")
	cmd.Flags().IntVar(&baseCandidates, "base-candidates", 0, "override base_candidates from config")
	return cmd
}

// ── pins ──────────────────────────────────────────────────────────────────────

func pinsCmd(ctx context.Context, cfgPath *string) *cobra.Command {
	pins := &cobra.Command{
		Use:   "pins",
		Short: "Check and update pinned OS packages in Dockerfiles",
	}
	pins.AddCommand(pinsCheckCmd(ctx, cfgPath))
	pins.AddCommand(pinsUpdateCmd(ctx, cfgPath))
	return pins
}

func pinsCheckCmd(ctx context.Context, cfgPath *string) *cobra.Command {
	var dockerfilePath string

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check pinned OS package versions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
				return writeStructuredError(map[string]string{
					"error": "dockerfile not found",
					"path":  dockerfilePath,
				})
			}
			_, _, err := loadConfig(ctx, *cfgPath)
			if err != nil {
				return writeStructuredError(structuredScanErr(err))
			}

			// TODO M3: wire pin analysis pipeline
			fmt.Fprintln(os.Stderr, "pins check: not yet implemented")
			return nil
		},
	}
	cmd.Flags().StringVar(&dockerfilePath, "dockerfile", "Dockerfile", "path to Dockerfile")
	return cmd
}

func pinsUpdateCmd(ctx context.Context, cfgPath *string) *cobra.Command {
	var (
		dockerfilePath string
		openPR         bool
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update pinned OS packages and open a pull request",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
				return writeStructuredError(map[string]string{
					"error": "dockerfile not found",
					"path":  dockerfilePath,
				})
			}
			_, _, err := loadConfig(ctx, *cfgPath)
			if err != nil {
				return writeStructuredError(structuredScanErr(err))
			}
			_ = openPR

			// TODO M4: wire pin update pipeline
			fmt.Fprintln(os.Stderr, "pins update: not yet implemented")
			return nil
		},
	}
	cmd.Flags().StringVar(&dockerfilePath, "dockerfile", "Dockerfile", "path to Dockerfile")
	cmd.Flags().BoolVar(&openPR, "open-pr", false, "open a pull request with updates")
	return cmd
}

// ── ci ────────────────────────────────────────────────────────────────────────

func ciCmd(ctx context.Context, cfgPath *string) *cobra.Command {
	var (
		imageRef      string
		baseImageRef  string
		dockerfilePath string
		formats       []string
	)

	cmd := &cobra.Command{
		Use:   "ci",
		Short: "Run full attribution + policy evaluation for CI",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := loadConfig(ctx, *cfgPath)
			if err != nil {
				return writeStructuredError(structuredScanErr(err))
			}

			// FR-25: new_only requires --base-image-ref (F1 gate)
			if cfg.Policy.NewOnly && baseImageRef == "" {
				return writeStructuredError(map[string]string{
					"error": "new_only requires --base-image-ref",
					"hint":  "pass the target branch image ref with --base-image-ref",
				})
			}
			_ = imageRef
			_ = dockerfilePath
			_ = formats

			// TODO M4: wire full CI pipeline
			fmt.Fprintln(os.Stderr, "ci: not yet implemented")
			return nil
		},
	}
	cmd.Flags().StringVar(&imageRef, "image", "", "image reference to scan (required)")
	cmd.Flags().StringVar(&baseImageRef, "base-image-ref", "", "baseline image ref for new_only diff")
	cmd.Flags().StringVar(&dockerfilePath, "dockerfile", "Dockerfile", "path to Dockerfile")
	cmd.Flags().StringArrayVar(&formats, "format", []string{"md", "json"}, "output formats")
	return cmd
}

// structuredScanErr converts a scan error to a JSON-serialisable map.
func structuredScanErr(err error) map[string]string {
	switch e := err.(type) {
	case *scan.ErrToolMissing:
		return map[string]string{"error": e.Tool + " not found", "hint": e.Hint}
	case *scan.ErrVersionTooOld:
		return map[string]string{
			"error":    e.Tool + " version too old",
			"found":    e.Found,
			"required": e.Required,
		}
	default:
		return map[string]string{"error": err.Error()}
	}
}
