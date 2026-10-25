package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/Arham1716/imgowner/internal/attribution"
	"github.com/Arham1716/imgowner/internal/config"
	"github.com/Arham1716/imgowner/internal/dockerfile"
	"github.com/Arham1716/imgowner/internal/history"
	"github.com/Arham1716/imgowner/internal/image"
	"github.com/Arham1716/imgowner/internal/pins"
	"github.com/Arham1716/imgowner/internal/pipeline"
	"github.com/Arham1716/imgowner/internal/report"
	"github.com/Arham1716/imgowner/internal/safeio"
	"github.com/Arham1716/imgowner/internal/scan"
	"github.com/Arham1716/imgowner/internal/scm"
)

// version, commit and date are set via -ldflags at build time (see
// .goreleaser.yml); they stay "dev"/"none"/"unknown" for a local `go build`.
// A signed release's SBOM and cosign signature cover these exact values, so
// `imgowner version` is how a user confirms which build they actually have.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// exitError carries a specific OS exit code through cobra's error path.
// reported is true when the error has already been written to stderr (as a
// structured JSON error), so main must not print it a second time.
type exitError struct {
	code     int
	cause    error
	reported bool
}

func (e *exitError) Error() string { return e.cause.Error() }
func (e *exitError) Unwrap() error { return e.cause }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := rootCmd(ctx).ExecuteContext(ctx); err != nil {
		// Cobra's own messages are silenced (SilenceErrors) so that structured
		// errors aren't followed by a duplicate; everything not yet reported
		// is printed here. A failure must never exit with nothing on stderr.
		var ee *exitError
		if errors.As(err, &ee) {
			if !ee.reported {
				fmt.Fprintf(os.Stderr, "imgowner: %v\n", ee.cause)
			}
			os.Exit(ee.code)
		}
		fmt.Fprintf(os.Stderr, "imgowner: %v\nRun 'imgowner --help' for usage.\n", err)
		os.Exit(2) // generic tool/config error (unknown flag, unknown command, ...)
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
	// An explicitly named --config must exist; only the default path may be
	// absent (a project without a config file runs on built-in defaults).
	root.PersistentPreRun = func(cmd *cobra.Command, _ []string) {
		cfgExplicit = cmd.Flags().Changed("config")
	}
	root.Version = fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
	root.SetVersionTemplate("imgowner {{.Version}}\n")

	root.AddCommand(
		attributeCmd(ctx, &cfgPath),
		pinsCmd(ctx, &cfgPath),
		ciCmd(ctx, &cfgPath),
		dashboardCmd(ctx, &cfgPath),
	)
	return root
}

// cfgExplicit records whether --config was given on the command line.
var cfgExplicit bool

// readConfig loads the config file: required when named with --config,
// optional at the default path.
func readConfig(path string) (config.Config, error) {
	if cfgExplicit {
		return config.LoadRequired(path)
	}
	return config.Load(path)
}

// loadConfig reads and validates the config file, then checks Trivy version.
// Returns the config and the resolved Trivy version string.
func loadConfig(ctx context.Context, cfgPath string) (config.Config, string, error) {
	cfg, err := readConfig(cfgPath)
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
	if err := json.NewEncoder(os.Stderr).Encode(payload); err != nil {
		return toolErr(fmt.Errorf("%v (and writing the error failed: %w)", payload, err))
	}
	return &exitError{code: 2, cause: fmt.Errorf("tool error"), reported: true}
}

// ── attribute ────────────────────────────────────────────────────────────────

func attributeCmd(ctx context.Context, cfgPath *string) *cobra.Command {
	var (
		imageRef       string
		dockerfilePath string
		baseDigest     string
		formats        []string
		outputDir      string
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
			// Settled before the scan, so a bad --format fails in a second,
			// not after a ten-minute scan.
			fmts, outDir, err := reportTarget(formats, outputDir, cfg, true)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
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

			// Write reports (FR-28): one file per format, or one format on stdout.
			written, err := report.Write(report.Request{
				Image:      imageRef,
				Digest:     res.Digest,
				BaseRef:    res.BaseRef,
				Findings:   res.Findings,
				Candidates: res.Candidates,
				Formats:    fmts,
				OutputDir:  outDir,
				Dockerfile: dockerfilePath,
			})
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			announce(written)
			recordHistory(cfg, history.Input{
				Command:    "attribute",
				Image:      imageRef,
				Digest:     res.Digest,
				BaseRef:    res.BaseRef,
				Dockerfile: dockerfilePath,
				Findings:   res.Findings,
				Candidates: res.Candidates,
			})
			return nil
		},
	}

	cmd.Flags().StringVar(&imageRef, "image", "", "image reference to scan (required)")
	cmd.Flags().StringVar(&dockerfilePath, "dockerfile", "Dockerfile", "path to Dockerfile")
	cmd.Flags().StringVar(&baseDigest, "base-digest", "", "override base image digest")
	cmd.Flags().StringArrayVar(&formats, "format", nil, "report formats, comma-separated or repeated (md,json,sarif); overrides report.formats")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "directory for report files (default: stdout for a single --format, else report.output_dir); '-' forces stdout")
	cmd.Flags().IntVar(&baseCandidates, "base-candidates", 0, "override base_candidates from config")
	return cmd
}

// ── pins ──────────────────────────────────────────────────────────────────────

func pinsCmd(ctx context.Context, cfgPath *string) *cobra.Command {
	pins := &cobra.Command{
		Use:   "pins",
		Short: "Check and update pinned OS packages in Dockerfiles",
		// Without RunE cobra prints help and exits 0 for `pins frobnicate`,
		// so a typo in a CI script would pass silently.
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return toolErr(fmt.Errorf("unknown command %q for %q (use check or update)", args[0], cmd.CommandPath()))
			}
			return cmd.Help()
		},
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
			dfContent, err := safeio.ReadFile(dockerfilePath, safeio.MaxDockerfile)
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
			warnUnlookupable(pinList)
			pinsImage := imageRef
			if pinsImage == "" {
				if final := df.FinalStage(); final != nil {
					pinsImage = df.ResolveBaseRef(final)
				}
			}
			if len(pinList) == 0 {
				recordHistory(cfg, history.Input{Command: "pins-check", Image: pinsImage, Dockerfile: dockerfilePath})
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

			recordHistory(cfg, history.Input{
				Command:    "pins-check",
				Image:      pinsImage,
				Dockerfile: dockerfilePath,
				Pins:       pinList,
			})

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
	// Group by stage index: grouping by name put every unnamed stage into one
	// group and looked them all up in the first one's image.
	type group struct {
		ref  string
		idxs []int
	}
	groups := make(map[int]*group)
	for i, p := range pinList {
		if groups[p.StageIndex] == nil {
			ref := imageRefOverride
			if ref == "" && p.StageIndex >= 0 && p.StageIndex < len(df.Stages) {
				ref = df.ResolveBaseRef(&df.Stages[p.StageIndex])
			}
			// No ref resolved — skip this stage (best effort).
			groups[p.StageIndex] = &group{ref: ref}
		}
		groups[p.StageIndex].idxs = append(groups[p.StageIndex].idxs, i)
	}

	for _, g := range groups {
		if g.ref == "" {
			continue
		}
		stgPins := make([]pins.Pin, len(g.idxs))
		for j, idx := range g.idxs {
			stgPins[j] = pinList[idx]
		}
		// pins.lookup_timeout (NFR-09) bounds each stage's container run.
		lookupCtx, cancelLookup := context.WithTimeout(ctx, cfg.Pins.LookupDuration())
		updated, err := pins.LookupVersions(lookupCtx, rt, g.ref, stgPins)
		cancelLookup()
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

// ciPins runs the pin check inside ci (FR-23). It never fails the command:
// a missing container runtime or a failed lookup is reported in the notes
// (FR-27: "never skip silently") and the attribution result stands. Pins
// whose upgrade reaches the fixed version of an attributed CVE on that
// package are promoted to fixes-CVE(s) (FR-16).
func ciPins(ctx context.Context, cfg config.Config, dockerfilePath string, findings []attribution.Finding) ([]pins.Pin, string) {
	if !cfg.Pins.Enabled {
		return nil, ""
	}
	content, err := safeio.ReadFile(dockerfilePath, safeio.MaxDockerfile)
	if err != nil {
		return nil, "Pin check skipped — " + err.Error()
	}
	df, err := dockerfile.ParseBytes(content)
	if err != nil {
		return nil, "Pin check skipped — " + err.Error()
	}
	pinList, err := pins.Extract(content, df, cfg.Pins.IgnorePackages...)
	if err != nil {
		return nil, "Pin check skipped — " + err.Error()
	}
	if len(pinList) == 0 {
		return nil, ""
	}
	warnUnlookupable(pinList)
	rt, err := pins.DetectRuntime(ctx)
	if err != nil {
		note := "Pin check skipped — no container runtime detected (install Docker or Podman to check pinned versions)"
		fmt.Fprintln(os.Stderr, "warning: "+note)
		return pinList, note
	}
	pinList, err = runPinLookup(ctx, rt, pinList, df, "", cfg)
	if err != nil {
		note := "Pin check incomplete — " + err.Error()
		fmt.Fprintln(os.Stderr, "warning: "+note)
		return pinList, note
	}
	return pins.ApplyCVEFixes(pinList, cveFixesFor(pinList, findings)), ""
}

// cveFixesFor maps each pinned package to the attributed CVEs its available
// upgrade would fix: findings on that package, at the pinned version, whose
// fixed version the upgrade reaches.
func cveFixesFor(pinList []pins.Pin, findings []attribution.Finding) map[string][]string {
	out := map[string][]string{}
	for _, p := range pinList {
		if p.Available == "" {
			continue
		}
		seen := map[string]bool{}
		for _, f := range findings {
			if f.Package != p.Package || f.InstalledVersion != p.Version || f.FixedVersion == "" || seen[f.CVE] {
				continue
			}
			for _, fixed := range strings.Split(f.FixedVersion, ",") {
				if fixed = strings.TrimSpace(fixed); fixed != "" && pins.VersionAtLeast(p.Available, fixed) {
					out[p.Package] = append(out[p.Package], f.CVE)
					seen[f.CVE] = true
					break
				}
			}
		}
	}
	return out
}

// scmClient detects the SCM and builds its client; both failures are errors
// the caller reports (they used to fall through to a silent no-op client).
func scmClient(cfg config.Config) (scm.PRClient, error) {
	provider, err := scm.Detect(cfg.SCM.Provider)
	if err != nil {
		return nil, err
	}
	return scm.NewClient(provider)
}

// postComment renders the Markdown report and posts or updates the PR comment.
func postComment(ctx context.Context, cfg config.Config, prID string, req report.Request) error {
	client, err := scmClient(cfg)
	if err != nil {
		return err
	}
	var buf strings.Builder
	if err := report.WriteToWriter(&buf, req); err != nil {
		return err
	}
	return client.EnsureComment(ctx, prID, buf.String())
}

// repoRelativePath turns the Dockerfile path into the repository-relative,
// forward-slash path the SCM API commits to. The repository root is the CI
// workspace (GitHub Actions, Azure Pipelines) or `git rev-parse
// --show-toplevel`; a Dockerfile outside it is an error.
func repoRelativePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	root := os.Getenv("GITHUB_WORKSPACE")
	if root == "" {
		root = os.Getenv("BUILD_SOURCESDIRECTORY")
	}
	if root == "" {
		out, err := exec.Command("git", "-C", filepath.Dir(abs), "rev-parse", "--show-toplevel").Output()
		if err != nil {
			return "", fmt.Errorf("locating the repository root for %s: not in a git checkout", path)
		}
		root = strings.TrimSpace(string(out))
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	// Resolve symlinks on both sides so /tmp vs /private/tmp style aliases match.
	if r, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootAbs = r
	}
	if a, err := filepath.EvalSymlinks(abs); err == nil {
		abs = a
	}
	rel, err := filepath.Rel(rootAbs, abs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("%s is outside the repository at %s", path, rootAbs)
	}
	return filepath.ToSlash(rel), nil
}

// warnUnlookupable prints why each variable or unsupported pin is skipped
// (FR-13, FR-14), on stderr so --format json output stays clean.
func warnUnlookupable(pinList []pins.Pin) {
	for _, p := range pinList {
		if !p.Lookupable() && p.Note != "" {
			fmt.Fprintf(os.Stderr, "warning: %s (line %d) not checked: %s\n", p.Package, p.Line, p.Note)
		}
	}
}

func printPinsSummary(pinList []pins.Pin) {
	counts := map[pins.Status]int{}
	for _, p := range pinList {
		counts[p.Status]++
	}
	fmt.Printf("Pinned packages: %d\n", len(pinList))
	fmt.Printf("  current=%d  update-available=%d  fixes-CVE(s)=%d  unavailable=%d  unknown=%d  variable=%d  unsupported=%d\n",
		counts[pins.StatusCurrent],
		counts[pins.StatusUpdateAvailable],
		counts[pins.StatusFixesCVEs],
		counts[pins.StatusUnavailable],
		counts[pins.StatusUnknown],
		counts[pins.StatusVariable],
		counts[pins.StatusUnsupported],
	)
	for _, p := range pinList {
		switch p.Status {
		case pins.StatusUpdateAvailable:
			fmt.Printf("  UPDATE   %-30s %s → %s (line %d)\n", p.Package, p.Version, p.Available, p.Line)
		case pins.StatusFixesCVEs:
			fmt.Printf("  FIX-CVE  %-30s %s → %s (line %d) [%d CVE(s)]\n", p.Package, p.Version, p.Available, p.Line, len(p.FixesCVEs))
		case pins.StatusUnavailable:
			if p.Available != "" {
				fmt.Printf("  MISSING  %-30s %s → %s (line %d) [pinned version left the repository]\n", p.Package, p.Version, p.Available, p.Line)
			} else {
				fmt.Printf("  MISSING  %-30s %s (line %d) [package not in the repository: manual action]\n", p.Package, p.Version, p.Line)
			}
		case pins.StatusVariable, pins.StatusUnsupported:
			fmt.Printf("  SKIPPED  %-30s %s (line %d) [%s]\n", p.Package, p.Version, p.Line, p.Note)
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

			dfContent, err := safeio.ReadFile(dockerfilePath, safeio.MaxDockerfile)
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
			warnUnlookupable(pinList)

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

			// Open or update a pull request (FR-21, FR-22).
			client, err := scmClient(cfg)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error(),
					"hint": "the Dockerfile was updated locally; set scm.provider or run inside GitHub Actions / Azure DevOps to open a PR"})
			}
			repoPath, err := repoRelativePath(dockerfilePath)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			res, err := client.OpenOrUpdatePR(ctx, scm.PRRequest{
				BranchPrefix:  cfg.SCM.BranchPrefix,
				BaseBranch:    baseBranch,
				Title:         "chore: update pinned OS package versions",
				Body:          buildPinsPRBody(pinList),
				Labels:        cfg.SCM.Labels,
				File:          scm.FileChange{Path: repoPath, Content: updated},
				CommitMessage: fmt.Sprintf("chore: update %d pinned OS package version(s) in %s", len(edits), repoPath),
			})
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			for _, w := range res.Warnings {
				fmt.Fprintln(os.Stderr, "warning: "+w)
			}
			verb := "Updated"
			if res.Created {
				verb = "Opened"
			}
			fmt.Printf("%s PR %s (branch %s)\n", verb, res.URL, res.Branch)
			return nil
		},
	}
	cmd.Flags().StringVar(&dockerfilePath, "dockerfile", "Dockerfile", "path to Dockerfile")
	cmd.Flags().StringVar(&imageRef, "image", "", "override base image ref for container lookup")
	cmd.Flags().BoolVar(&openPR, "open-pr", false, "open a pull request with updates")
	cmd.Flags().StringVar(&baseBranch, "base-branch", "", "target branch for the pull request (default: the repository's default branch)")
	return cmd
}

func buildPinsPRBody(pinList []pins.Pin) string {
	var sb strings.Builder
	var updates, bumped, manual []pins.Pin
	for _, p := range pinList {
		switch {
		case p.Status == pins.StatusUpdateAvailable || p.Status == pins.StatusFixesCVEs:
			updates = append(updates, p)
		case p.Status == pins.StatusUnavailable && p.Available != "":
			bumped = append(bumped, p)
		case p.Status == pins.StatusUnavailable:
			manual = append(manual, p)
		}
	}
	sb.WriteString("## Pinned OS package updates\n\n")
	if len(updates) > 0 {
		sb.WriteString("| Package | Old | New | Status |\n|---|---|---|---|\n")
		for _, p := range updates {
			fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n", p.Package, p.Version, p.Available, p.Status)
		}
		sb.WriteString("\n")
	}
	if len(bumped) > 0 {
		// FR-18
		sb.WriteString("### Unavailable pins bumped\n\nPreviously unavailable — the build would have failed with these pins.\n\n")
		sb.WriteString("| Package | Old (gone) | New |\n|---|---|---|\n")
		for _, p := range bumped {
			fmt.Fprintf(&sb, "| %s | %s | %s |\n", p.Package, p.Version, p.Available)
		}
		sb.WriteString("\n")
	}
	if len(manual) > 0 {
		// FR-19
		sb.WriteString("### Requires manual action\n\nThese packages are no longer in the OS repository at all; their pins were left unchanged.\n\n")
		sb.WriteString("| Package | Last pinned version | Line |\n|---|---|---|\n")
		for _, p := range manual {
			fmt.Fprintf(&sb, "| %s | %s | %d |\n", p.Package, p.Version, p.Line)
		}
		sb.WriteString("\n")
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
			if prID != "" {
				if err := scm.ValidPRID(prID); err != nil {
					return writeStructuredError(map[string]string{"error": err.Error()})
				}
			}

			cfg, trivyVer, err := loadConfig(ctx, *cfgPath)
			if err != nil {
				return writeStructuredError(structuredScanErr(err))
			}
			fmts, outDir, err := reportTarget(formats, outputDir, cfg, false)
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
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
				findings, err = filterNewFindings(ctx, findings, baseImageRef, runner, cfg.Scan.Platform)
				if err != nil {
					// Failing open here would report every existing CVE as new;
					// failing closed says exactly what went wrong.
					return writeStructuredError(map[string]string{
						"error": "new_only baseline could not be scanned",
						"ref":   baseImageRef,
						"cause": err.Error(),
						"hint":  "check --base-image-ref, or turn policy.new_only off for this run",
					})
				}
			}

			// ── Pin check (FR-23, FR-27) ─────────────────────────────────
			pinList, pinsNote := ciPins(ctx, cfg, dockerfilePath, findings)

			// ── Policy evaluation ─────────────────────────────────────────
			breaching := evaluatePolicy(findings, cfg)
			verdict := "passed"
			if breaching > 0 {
				verdict = fmt.Sprintf("failed — %d finding(s) at or above %s owned by %s",
					breaching, strings.Join(cfg.Policy.FailOn, "/"), enforcedOwners(cfg))
			}

			// ── Report writing (FR-28) ────────────────────────────────────
			written, err := report.Write(report.Request{
				Image:      imageRef,
				Digest:     res.Digest,
				BaseRef:    baseRef,
				Findings:   findings,
				Candidates: candidates,
				Pins:       pinList,
				PinsNote:   pinsNote,
				Verdict:    verdict,
				OutputDir:  outDir,
				Formats:    fmts,
				Dockerfile: dockerfilePath,
			})
			if err != nil {
				return writeStructuredError(map[string]string{"error": err.Error()})
			}
			announce(written)
			// Recorded before the policy verdict is returned: a breach (exit 1)
			// is a completed scan and belongs in the history too (FR-31).
			recordHistory(cfg, history.Input{
				Command:    "ci",
				Image:      imageRef,
				Digest:     res.Digest,
				BaseRef:    baseRef,
				Dockerfile: dockerfilePath,
				Findings:   findings,
				Candidates: candidates,
				Pins:       pinList,
			})

			// ── SCM comment (FR-24) ───────────────────────────────────────
			// A failure here doesn't change the verdict, but it must be visible:
			// v0.5.0 dropped every error, so a missing token meant no comment
			// and no clue why.
			if prID != "" {
				if err := postComment(ctx, cfg, prID, report.Request{
						Image:      imageRef,
						Digest:     res.Digest,
						BaseRef:    baseRef,
						Findings:   findings,
						Candidates: candidates,
						Pins:       pinList,
						PinsNote:   pinsNote,
						Verdict:    verdict,
					Formats:    []string{"md"},
					Dockerfile: dockerfilePath,
				}); err != nil {
					fmt.Fprintf(os.Stderr, "warning: PR comment not posted: %v\n", err)
				}
			}

			if breaching > 0 {
				return policyErr(fmt.Errorf("policy breach: %d finding(s) at or above policy.fail_on %v owned by %s",
					breaching, cfg.Policy.FailOn, enforcedOwners(cfg)))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&imageRef, "image", "", "image reference to scan (required)")
	cmd.Flags().StringVar(&baseImageRef, "base-image-ref", "", "baseline image ref for new_only diff")
	cmd.Flags().StringVar(&baseDigest, "base-digest", "", "digest of the base image used at build time (sha256:...)")
	cmd.Flags().StringVar(&dockerfilePath, "dockerfile", "Dockerfile", "path to Dockerfile")
	cmd.Flags().StringArrayVar(&formats, "format", nil, "report formats, comma-separated or repeated (md,json,sarif); overrides report.formats")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "directory for report files (default report.output_dir); '-' writes a single format to stdout")
	cmd.Flags().StringVar(&prID, "pr-id", "", "PR number/ID to post attribution comment on")
	cmd.Flags().BoolVar(&failOnBaseMismatch, "fail-on-base-mismatch", true,
		"exit with an error when the base image boundary cannot be verified")
	return cmd
}

// reportTarget resolves the formats and output directory from flags over
// config, validating them before any scan runs.
//
// singleToStdout keeps attribute's long-standing behaviour: one format named
// with --format and no --output-dir prints to stdout, which scripts and the
// released VS Code extension (`attribute --format json`) parse. Several
// formats never share stdout; they go to files (FR-28).
func reportTarget(flagFormats []string, flagDir string, cfg config.Config, singleToStdout bool) ([]string, string, error) {
	src := flagFormats
	if len(src) == 0 {
		src = cfg.Report.Formats
	}
	fmts, err := report.ParseFormats(src)
	if err != nil {
		return nil, "", err
	}
	dir := flagDir
	if dir == "" {
		dir = cfg.Report.OutputDir
		if singleToStdout && len(flagFormats) > 0 && len(fmts) == 1 {
			dir = report.Stdout
		}
	}
	if dir == report.Stdout && len(fmts) > 1 {
		return nil, "", fmt.Errorf("--output-dir - writes to stdout, which holds one format; got %s", strings.Join(fmts, ", "))
	}
	return fmts, dir, nil
}

// announce tells the user (on stderr, keeping stdout clean) where the
// reports went.
func announce(paths []string) {
	for _, p := range paths {
		fmt.Fprintf(os.Stderr, "wrote %s\n", p)
	}
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

// enforcedOwners describes policy.enforce_owners for the breach message.
func enforcedOwners(cfg config.Config) string {
	if len(cfg.Policy.EnforceOwners) == 0 {
		return "any owner"
	}
	return strings.Join(cfg.Policy.EnforceOwners, ", ")
}

// evaluatePolicy checks findings against fail_on severities and enforce_owners
// (FR-27). Returns the number of breaching findings; 0 means the policy passed.
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

	breaching := 0
	for _, f := range findings {
		if !failSev[strings.ToUpper(f.Severity)] {
			continue
		}
		// If enforce_owners is configured, only fail for owners in the set.
		if len(enforceSet) > 0 && !enforceSet[strings.ToLower(string(f.Owner))] {
			continue
		}
		breaching++
	}
	return breaching
}

// filterNewFindings scans baseImageRef and returns only findings whose CVE ID
// is NOT present in the baseline scan (FR-25 new_only mode). A baseline that
// can't be resolved or scanned is an error, never "everything is new".
func filterNewFindings(
	ctx context.Context,
	findings []attribution.Finding,
	baseImageRef string,
	runner *scan.Runner,
	platform string,
) ([]attribution.Finding, error) {
	baseInfo, err := image.ResolveAny(ctx, baseImageRef, platform)
	if err != nil {
		return nil, err
	}
	defer func() { _ = baseInfo.Close() }()
	baseResult, err := pipeline.ScanImage(ctx, runner, baseInfo)
	if err != nil {
		return nil, err
	}

	// Build CVE set present in the baseline image.
	baselineCVEs := make(map[string]bool)
	for _, t := range baseResult.Results {
		for _, v := range t.Vulnerabilities {
			baselineCVEs[v.VulnerabilityID] = true
		}
	}

	newOnly := []attribution.Finding{}
	for _, f := range findings {
		if !baselineCVEs[f.CVE] {
			newOnly = append(newOnly, f)
		}
	}
	return newOnly, nil
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
	case *config.ErrUnknownKey:
		return map[string]string{"error": "unknown config key", "key": e.Key, "line": strconv.Itoa(e.Line)}
	case *config.ErrInvalidConfig:
		return map[string]string{"error": "invalid config", "key": e.Key, "reason": e.Reason}
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
