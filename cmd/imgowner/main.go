package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/config"
	"github.com/Arham1716/imgowner/internal/dockerfile"
	"github.com/Arham1716/imgowner/internal/image"
	"github.com/Arham1716/imgowner/internal/pins"
	"github.com/Arham1716/imgowner/internal/pipeline"
	"github.com/Arham1716/imgowner/internal/report"
	"github.com/Arham1716/imgowner/internal/scan"
	"github.com/Arham1716/imgowner/internal/scm"
)

// exitError carries a specific OS exit code through cobra's error path.
type exitError struct {
	code  int
	cause error
}

func (e *exitError) Error() string { return e.cause.Error() }
func (e *exitError) Unwrap() error { return e.cause }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := rootCmd(ctx).ExecuteContext(ctx); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(2) // generic tool/config error
	}
}

// toolErr wraps an error as exit-code 2 (tool/config error per spec).
func toolErr(err error) error {
	if err == nil {
		return nil
	}
	return &exitError{code: 2, cause: err}
}

// policyErr wraps an error as exit-code 1 (policy breach per spec).
func policyErr(err error) error {
	if err == nil {
		return nil
	}
	return &exitError{code: 1, cause: err}
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

// writeStructuredError writes a JSON error to stderr and returns an exitError
// with code 2 so the process exits with the correct tool-error code.
func writeStructuredError(payload any) error {
	_ = json.NewEncoder(os.Stderr).Encode(payload)
	return toolErr(fmt.Errorf("tool error"))
}

// ── attribute ────────────────────────────────────────────────────────────────

func attributeCmd(ctx context.Context, cfgPath *string) *cobra.Command {
	var (
		imageRef       string
		dockerfilePath string
		baseDigest     string
		formats        []string
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

			res, err := pipeline.Attribute(ctx, pipeline.AttributeRequest{
				ImageRef:       imageRef,
				DockerfilePath: dockerfilePath,
				BaseDigest:     baseDigest,
				Platform:       cfg.Scan.Platform,
				TrivyVersion:   trivyVer,
				Timeout:        cfg.Scan.Timeout(),
				BaseCandidates: n,
			})
			if err != nil {
				return writeStructuredError(structuredScanErr(err))
			}
			warnAboutAttribution(res)

			// Write reports (FR-21, FR-22, FR-23).
			if err := report.Write(report.Request{
				Image:      imageRef,
				BaseRef:    res.BaseRef,
				Findings:   res.Findings,
				Candidates: res.Candidates,
				Formats:    formats,
			}); err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
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
		format         string
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

			pinList, err := pins.Extract(dfContent, df, cfg.Pins.IgnorePackages...)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			if len(pinList) == 0 {
				if strings.EqualFold(format, "json") {
					fmt.Println("[]")
				} else {
					fmt.Println("No pinned OS packages found.")
				}
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

			if strings.EqualFold(format, "json") {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(pinList)
			}
			printPinsSummary(pinList)
			return nil
		},
	}
	cmd.Flags().StringVar(&dockerfilePath, "dockerfile", "Dockerfile", "path to Dockerfile")
	cmd.Flags().StringVar(&imageRef, "image", "", "override the base image ref for container lookup")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
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
		var lookupErr *pins.LookupFailedError
		if errors.As(err, &lookupErr) {
			// Warn on stderr, keep going: stdout must stay clean JSON for
			// --format json, and other stages may still look up fine.
			fmt.Fprintf(os.Stderr, "warning: %v\n", lookupErr)
		} else if err != nil {
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
		imageRef       string
		openPR         bool
		baseBranch     string
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
			cfg, _, err := loadConfig(ctx, *cfgPath)
			if err != nil {
				return writeStructuredError(structuredScanErr(err))
			}

			dfContent, err := os.ReadFile(dockerfilePath)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			df, err := dockerfile.ParseBytes(dfContent)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}

			pinList, err := pins.Extract(dfContent, df, cfg.Pins.IgnorePackages...)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			if len(pinList) == 0 {
				fmt.Println("No pinned OS packages found.")
				return nil
			}

			rt, err := pins.DetectRuntime(ctx)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			pinList, err = runPinLookup(ctx, rt, pinList, df, imageRef, cfg)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}

			// Apply byte-level edits to Dockerfile (FR-17, Story 3.1).
			edits := pins.PlanEdits(pinList)
			if len(edits) == 0 {
				fmt.Println("All pinned packages are current.")
				return nil
			}
			updated, err := pins.ApplyEdits(dfContent, edits)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			if err := pins.WriteDockerfile(dockerfilePath, updated); err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			fmt.Printf("Updated %d pin(s) in %s\n", len(edits), dockerfilePath)

			if !openPR {
				return nil
			}

			// Open or update a pull request (Story 3.2, FR-18).
			provider, _ := scm.Detect(cfg.SCM.Provider)
			client, err := scm.NewClient(provider)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			prBody := buildPinsPRBody(pinList)
			prURL, err := client.OpenOrUpdatePR(ctx, scm.PRRequest{
				HeadBranch: "imgowner/pin-updates",
				BaseBranch: baseBranch,
				Title:      "chore: update pinned OS package versions",
				Body:       prBody,
			})
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			fmt.Printf("PR: %s\n", prURL)
			return nil
		},
	}
	cmd.Flags().StringVar(&dockerfilePath, "dockerfile", "Dockerfile", "path to Dockerfile")
	cmd.Flags().StringVar(&imageRef, "image", "", "override base image ref for container lookup")
	cmd.Flags().BoolVar(&openPR, "open-pr", false, "open a pull request with updates")
	cmd.Flags().StringVar(&baseBranch, "base-branch", "main", "target branch for the pull request")
	return cmd
}

func buildPinsPRBody(pinList []pins.Pin) string {
	var sb strings.Builder
	sb.WriteString("## Pinned OS package updates\n\n")
	sb.WriteString("| Package | Old | New | Status |\n|---|---|---|---|\n")
	for _, p := range pinList {
		if p.Status == pins.StatusUpdateAvailable || p.Status == pins.StatusFixesCVEs {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", p.Package, p.Version, p.Available, p.Status))
		}
	}
	return sb.String()
}

// ── ci ────────────────────────────────────────────────────────────────────────

func ciCmd(ctx context.Context, cfgPath *string) *cobra.Command {
	var (
		imageRef           string
		baseImageRef       string
		baseDigest         string
		dockerfilePath     string
		formats            []string
		outputDir          string
		prID               string
		failOnBaseMismatch bool
	)

	cmd := &cobra.Command{
		Use:   "ci",
		Short: "Run full attribution + policy evaluation for CI",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if imageRef == "" {
				return writeStructuredError(map[string]string{
					"error": "image reference required",
					"hint":  "pass --image <ref>",
				})
			}
			if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
				return writeStructuredError(map[string]string{
					"error": "dockerfile not found",
					"path":  dockerfilePath,
				})
			}

			cfg, trivyVer, err := loadConfig(ctx, *cfgPath)
			if err != nil {
				return writeStructuredError(structuredScanErr(err))
			}

			// FR-25: new_only requires --base-image-ref (F1 gate).
			if cfg.Policy.NewOnly && baseImageRef == "" {
				return writeStructuredError(map[string]string{
					"error": "new_only requires --base-image-ref",
					"hint":  "pass the target branch image ref with --base-image-ref",
				})
			}

			// ── Attribution pipeline ──────────────────────────────────────
			res, err := pipeline.Attribute(ctx, pipeline.AttributeRequest{
				ImageRef:       imageRef,
				DockerfilePath: dockerfilePath,
				BaseDigest:     baseDigest,
				Platform:       cfg.Scan.Platform,
				TrivyVersion:   trivyVer,
				Timeout:        cfg.Scan.Timeout(),
				BaseCandidates: cfg.Scan.BaseCandidates,
			})
			if err != nil {
				return writeStructuredError(structuredScanErr(err))
			}
			warnAboutAttribution(res)
			if !res.Base.Confident && failOnBaseMismatch {
				return writeStructuredError(map[string]string{
					"error":  "base image boundary could not be verified",
					"reason": res.Base.Reason,
					"hint":   "pass --base-digest sha256:... or set --fail-on-base-mismatch=false to continue",
				})
			}

			baseRef := res.BaseRef
			findings := res.Findings
			candidates := res.Candidates

			// ── new_only diff (FR-25) ─────────────────────────────────────
			// Filter to only CVEs that are new relative to the baseline image.
			if cfg.Policy.NewOnly && baseImageRef != "" {
				runner := &scan.Runner{
					TrivyVersion: trivyVer,
					Platform:     cfg.Scan.Platform,
					Timeout:      cfg.Scan.Timeout(),
				}
				findings = filterNewFindings(ctx, findings, baseImageRef, runner, cfg.Scan.Platform)
			}

			// ── Policy evaluation (FR-27) ─────────────────────────────────
			exitCode := evaluatePolicy(findings, cfg)

			// ── Report writing (FR-21, FR-22, FR-23) ─────────────────────
			fmts := formats
			if len(fmts) == 0 {
				fmts = cfg.Report.Formats
			}
			outDir := outputDir
			if outDir == "" {
				outDir = cfg.Report.OutputDir
			}
			if err := report.Write(report.Request{
				Image:      imageRef,
				BaseRef:    baseRef,
				Findings:   findings,
				Candidates: candidates,
				OutputDir:  outDir,
				Formats:    fmts,
			}); err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}

			// ── SCM comment (FR-24) ───────────────────────────────────────
			if prID != "" {
				provider, _ := scm.Detect(cfg.SCM.Provider)
				client, scmErr := scm.NewClient(provider)
				if scmErr == nil {
					var commentBuf strings.Builder
					_ = report.WriteToWriter(&commentBuf, report.Request{
						Image:      imageRef,
						BaseRef:    baseRef,
						Findings:   findings,
						Candidates: candidates,
						Formats:    []string{"md"},
					})
					_ = client.EnsureComment(ctx, prID, commentBuf.String())
				}
			}

			if exitCode != 0 {
				return policyErr(fmt.Errorf("policy breach: %d finding(s) at or above configured fail_on threshold", len(findings)))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&imageRef, "image", "", "image reference to scan (required)")
	cmd.Flags().StringVar(&baseImageRef, "base-image-ref", "", "baseline image ref for new_only diff")
	cmd.Flags().StringVar(&baseDigest, "base-digest", "", "digest of the base image used at build time (sha256:...)")
	cmd.Flags().StringVar(&dockerfilePath, "dockerfile", "Dockerfile", "path to Dockerfile")
	cmd.Flags().StringArrayVar(&formats, "format", nil, "output formats (md,json,sarif); overrides config")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "directory for report files; overrides config")
	cmd.Flags().StringVar(&prID, "pr-id", "", "PR number/ID to post attribution comment on")
	cmd.Flags().BoolVar(&failOnBaseMismatch, "fail-on-base-mismatch", true,
		"exit with an error when the base image boundary cannot be verified")
	return cmd
}

// warnAboutAttribution prints a single actionable warning when attribution had
// to degrade, instead of repeating the same reason on every finding.
func warnAboutAttribution(res *pipeline.AttributeResult) {
	if res == nil {
		return
	}
	if res.Squashed {
		fmt.Fprintf(os.Stderr,
			"warning: this image carries no per-layer provenance, so no finding can be traced to a "+
				"Dockerfile instruction.\n"+
				"  the image appears to have been squashed or flattened; rebuild without squashing "+
				"to enable attribution.\n")
		return
	}
	if res.Base != nil && !res.Base.Confident {
		fmt.Fprintf(os.Stderr,
			"warning: base image boundary could not be verified — all findings will be reported as "+
				"unattributed.\n  reason: %s\n", res.Base.Reason)
	}
}

// evaluatePolicy checks findings against fail_on severities and enforce_owners
// (FR-27). Returns 0 (success) or 1 (policy breach).
func evaluatePolicy(findings []attribution.Finding, cfg config.Config) int {
	failSev := make(map[string]bool, len(cfg.Policy.FailOn))
	for _, s := range cfg.Policy.FailOn {
		failSev[strings.ToUpper(s)] = true
	}

	// enforce_owners: if set, fail when a finding's owner is NOT in the allowed
	// set AND its severity is in fail_on. Owners not in enforce_owners are
	// considered exempt (e.g., "base" CVEs are the upstream's problem).
	enforceSet := make(map[string]bool, len(cfg.Policy.EnforceOwners))
	for _, o := range cfg.Policy.EnforceOwners {
		enforceSet[strings.ToLower(o)] = true
	}

	for _, f := range findings {
		if !failSev[strings.ToUpper(f.Severity)] {
			continue
		}
		// If enforce_owners is configured, only fail for owners in the set.
		if len(enforceSet) > 0 && !enforceSet[strings.ToLower(string(f.Owner))] {
			continue
		}
		return 1
	}
	return 0
}

// filterNewFindings scans baseImageRef and returns only findings whose CVE ID
// is NOT present in the baseline scan (FR-25 new_only mode).
func filterNewFindings(
	ctx context.Context,
	findings []attribution.Finding,
	baseImageRef string,
	runner *scan.Runner,
	platform string,
) []attribution.Finding {
	baseInfo, err := image.Resolve(ctx, baseImageRef, platform)
	if err != nil {
		// Can't reach baseline — return all findings (fail open, not closed).
		return findings
	}
	baseResult, err := runner.Scan(ctx, baseInfo.Ref, baseInfo.Digest)
	if err != nil {
		return findings
	}

	// Build CVE set present in the baseline image.
	baselineCVEs := make(map[string]bool)
	for _, t := range baseResult.Results {
		for _, v := range t.Vulnerabilities {
			baselineCVEs[v.VulnerabilityID] = true
		}
	}

	var newOnly []attribution.Finding
	for _, f := range findings {
		if !baselineCVEs[f.CVE] {
			newOnly = append(newOnly, f)
		}
	}
	return newOnly
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
	case *image.ErrRegistryAuth:
		return map[string]string{
			"error": "registry authentication failed",
			"host":  e.Host,
			"ref":   e.Ref,
			"hint":  "run `docker login " + e.Host + "` or configure registry credentials",
		}
	case *image.ErrRateLimited:
		return map[string]string{
			"error": "registry rate limit exceeded",
			"host":  e.Host,
			"hint":  "authenticate with `docker login " + e.Host + "` or lower scan.base_candidates",
		}
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
