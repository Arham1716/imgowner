package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/baserec"
	"github.com/Arham1716/imgowner/internal/config"
	"github.com/Arham1716/imgowner/internal/dockerfile"
	"github.com/Arham1716/imgowner/internal/image"
	"github.com/Arham1716/imgowner/internal/pins"
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

			n := cfg.Scan.BaseCandidates
			if baseCandidates > 0 {
				n = baseCandidates
			}

			// Resolve image digest (FR-01, F3, F4).
			info, err := image.Resolve(ctx, imageRef, cfg.Scan.Platform)
			if err != nil {
				return writeStructuredError(structuredScanErr(err))
			}

			// Scan image (FR-02); cache keyed by digest+trivyVersion (DQ-1).
			runner := &scan.Runner{TrivyVersion: trivyVer, Platform: cfg.Scan.Platform}
			result, err := runner.Scan(ctx, info.Ref, info.Digest)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}

			// Parse Dockerfile and build layer map (FR-03).
			df, err := dockerfile.Parse(dockerfilePath)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			finalStage := df.FinalStage()
			if finalStage == nil {
				return writeStructuredError(map[string]string{"error": "dockerfile has no stages"})
			}

			// Fetch image config and build layer map (FR-03).
			imgCF, err := info.Image.ConfigFile()
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			layerMap, err := image.BuildLayerMap(imgCF)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}

			// Identify base layers (FR-04).
			baseRef := df.ResolveBaseRef(finalStage)
			baseCF, err := image.Config(ctx, baseRef, cfg.Scan.Platform)
			baseLayerCount := 0
			if err == nil {
				baseLayerCount, _ = image.BaseLayerCount(imgCF, baseCF)
			}
			// On base resolution failure: fall to unattributed (F5/F6 DEFER path).

			// Classify findings (FR-05 through FR-08).
			findings := attribution.Classify(result.Results, layerMap, baseLayerCount)
			findings = attribution.MapToDockerfileLines(findings, layerMap)

			// Base image recommendation (FR-09, FR-10, FR-11).
			candidates, recErr := baserec.Recommend(ctx, baseRef, result, runner, cfg.Scan.Platform, n)
			_ = recErr // partial failure logged in candidates[i].FailReason

			// Print summary to stdout (full report writer comes in report package).
			printAttributionSummary(findings, candidates, baseRef)
			_ = formats
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
	var (
		dockerfilePath string
		imageRef       string
	)

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
			cfg, _, err := loadConfig(ctx, *cfgPath)
			if err != nil {
				return writeStructuredError(structuredScanErr(err))
			}

			// Parse Dockerfile and extract pinned packages (Story 2.1, FR-12).
			dfContent, err := os.ReadFile(dockerfilePath)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			df, err := dockerfile.ParseBytes(dfContent)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}

			pinList, err := pins.Extract(dfContent, df)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			if len(pinList) == 0 {
				fmt.Println("No pinned OS packages found.")
				return nil
			}

			// Version lookup via container run (Story 2.2, FR-14, FR-15).
			rt, err := pins.DetectRuntime(ctx)
			if err != nil {
				return writeStructuredError(map[string]string{
					"error": err.Error(),
					"hint":  "install docker or podman to enable pin version lookup",
				})
			}

			// Group pins by stage; resolve each stage's base image ref.
			pinList, err = runPinLookup(ctx, rt, pinList, df, imageRef, cfg)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}

			printPinsSummary(pinList)
			return nil
		},
	}
	cmd.Flags().StringVar(&dockerfilePath, "dockerfile", "Dockerfile", "path to Dockerfile")
	cmd.Flags().StringVar(&imageRef, "image", "", "override the base image ref for container lookup")
	return cmd
}

// runPinLookup calls LookupVersions for each stage group (FR-15: one container per stage).
func runPinLookup(
	ctx context.Context,
	rt pins.Runtime,
	pinList []pins.Pin,
	df *dockerfile.File,
	imageRefOverride string,
	cfg config.Config,
) ([]pins.Pin, error) {
	// Group by stage name.
	type group struct {
		ref  string
		idxs []int
	}
	groups := make(map[string]*group)
	for i, p := range pinList {
		if groups[p.Stage] == nil {
			// Resolve the base image ref for this stage.
			ref := imageRefOverride
			if ref == "" {
				for _, s := range df.Stages {
					if s.Name == p.Stage {
						ref = df.ResolveBaseRef(&s)
						break
					}
				}
			}
			// No ref resolved — skip this stage (best effort).
			_ = cfg
			groups[p.Stage] = &group{ref: ref}
		}
		groups[p.Stage].idxs = append(groups[p.Stage].idxs, i)
	}

	for _, g := range groups {
		if g.ref == "" {
			continue
		}
		stgPins := make([]pins.Pin, len(g.idxs))
		for j, idx := range g.idxs {
			stgPins[j] = pinList[idx]
		}
		updated, err := pins.LookupVersions(ctx, rt, g.ref, stgPins)
		if err != nil {
			return pinList, err
		}
		for j, idx := range g.idxs {
			pinList[idx] = updated[j]
		}
	}
	return pinList, nil
}

func printPinsSummary(pinList []pins.Pin) {
	counts := map[pins.Status]int{}
	for _, p := range pinList {
		counts[p.Status]++
	}
	fmt.Printf("Pinned packages: %d\n", len(pinList))
	fmt.Printf("  current=%d  update-available=%d  fixes-CVE(s)=%d  unavailable=%d  unknown=%d\n",
		counts[pins.StatusCurrent],
		counts[pins.StatusUpdateAvailable],
		counts[pins.StatusFixesCVEs],
		counts[pins.StatusUnavailable],
		counts[pins.StatusUnknown],
	)
	for _, p := range pinList {
		switch p.Status {
		case pins.StatusUpdateAvailable:
			fmt.Printf("  UPDATE   %-30s %s → %s (line %d)\n", p.Package, p.Version, p.Available, p.Line)
		case pins.StatusFixesCVEs:
			fmt.Printf("  FIX-CVE  %-30s %s → %s (line %d) [%d CVE(s)]\n", p.Package, p.Version, p.Available, p.Line, len(p.FixesCVEs))
		case pins.StatusUnavailable:
			fmt.Printf("  MISSING  %-30s %s (line %d)\n", p.Package, p.Version, p.Line)
		case pins.StatusCurrent:
			fmt.Printf("  OK       %-30s %s (line %d)\n", p.Package, p.Version, p.Line)
		default:
			fmt.Printf("  UNKNOWN  %-30s %s (line %d)\n", p.Package, p.Version, p.Line)
		}
	}
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

// printAttributionSummary writes a plain-text summary to stdout.
// The full Markdown/JSON/SARIF writer lives in internal/report (M1 final wire-up).
func printAttributionSummary(findings []attribution.Finding, candidates []baserec.Candidate, baseRef string) {
	counts := map[attribution.Owner]int{}
	for _, f := range findings {
		counts[f.Owner]++
	}
	fmt.Printf("Findings: %d total\n", len(findings))
	fmt.Printf("  base=%d  added-os=%d  app=%d  unattributed=%d\n",
		counts[attribution.OwnerBase],
		counts[attribution.OwnerAddedOS],
		counts[attribution.OwnerApp],
		counts[attribution.OwnerUnattributed],
	)
	fmt.Printf("Base: %s\n", baseRef)
	if len(candidates) > 0 && !candidates[0].Failed {
		fmt.Printf("Recommendation: FROM %s  (removes %d CVEs)\n",
			candidates[0].Ref, candidates[0].CVEsRemoved)
	}
}

// structuredErr converts known error types to a JSON-serialisable map.
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
	case *image.ErrImageNotFound:
		return map[string]string{"error": "image not found", "ref": e.Ref}
	case *image.ErrRegistryUnreachable:
		return map[string]string{
			"error": "registry unreachable",
			"host":  e.Host,
			"cause": e.Cause.Error(),
		}
	default:
		return map[string]string{"error": err.Error()}
	}
}
