package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Arham1716/imgowner/internal/safeio"
)

// Config is the fully resolved configuration for imgowner.
// Precedence: CLI flags > .imgowner.yaml > built-in defaults.
type Config struct {
	Version int     `yaml:"version"`
	Scan    Scan    `yaml:"scan"`
	Policy  Policy  `yaml:"policy"`
	Pins    Pins    `yaml:"pins"`
	Report  Report  `yaml:"report"`
	SCM     SCM     `yaml:"scm"`
	History History `yaml:"history"`
}

type Scan struct {
	Platform        string `yaml:"platform"`
	TrivyMinVersion string `yaml:"trivy_min_version"`
	TimeoutStr      string `yaml:"timeout"`
	BaseCandidates  int    `yaml:"base_candidates"`
}

type Policy struct {
	FailOn        []string `yaml:"fail_on"`
	EnforceOwners []string `yaml:"enforce_owners"`
	NewOnly       bool     `yaml:"new_only"`
}

type Pins struct {
	Enabled        bool     `yaml:"enabled"`
	Runtime        string   `yaml:"runtime"`
	LookupTimeout  string   `yaml:"lookup_timeout"`
	Stages         string   `yaml:"stages"`
	IgnorePackages []string `yaml:"ignore_packages"`
}

type Report struct {
	Formats   []string `yaml:"formats"`
	OutputDir string   `yaml:"output_dir"`
}

type SCM struct {
	Provider     string   `yaml:"provider"`
	Comment      string   `yaml:"comment"`
	BranchPrefix string   `yaml:"branch_prefix"`
	Labels       []string `yaml:"labels"`
}

// History configures the local scan history store (FR-31, FR-32). It lives
// on the user's own machine and is never transmitted anywhere (NFR-12).
type History struct {
	// Enabled turns recording off entirely; useful in CI, where nothing ever
	// reads the store.
	Enabled bool `yaml:"enabled"`
	// RetentionDays is how long a record is kept; older ones are deleted on
	// every write. Must be at least 1: zero would silently delete every
	// record the moment it is written, which is never what anyone means.
	RetentionDays int `yaml:"retention_days"`
	// Dir overrides the per-user default location (see history.DefaultDir).
	Dir string `yaml:"dir"`
}

// ErrInvalidConfig reports a config value that parsed but is not acceptable.
type ErrInvalidConfig struct {
	Key    string
	Reason string
}

func (e *ErrInvalidConfig) Error() string {
	return fmt.Sprintf("imgowner: invalid config %s: %s", e.Key, e.Reason)
}

// ErrUnknownKey reports a key the config file sets that imgowner doesn't
// have (FR-29), usually a typo that would otherwise be silently ignored.
type ErrUnknownKey struct {
	Key  string // dotted path, e.g. "scan.platfrom"
	Line int
}

func (e *ErrUnknownKey) Error() string {
	return fmt.Sprintf("imgowner: unknown config key %q (line %d)", e.Key, e.Line)
}

// Recognised values. Policy lists are compared case-insensitively, as the
// policy evaluation itself does.
var (
	severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	owners     = []string{"base", "added-os", "app", "unattributed"}
	formats    = []string{"md", "markdown", "json", "sarif"}
	providers  = []string{"auto", "github", "azure-devops"}
	runtimes   = []string{"auto", "docker", "podman"}
)

// Validate checks values that are structurally valid YAML but semantically
// unusable. Every value that changes what imgowner reports or enforces is
// checked here: a misspelt severity in policy.fail_on used to be accepted
// and silently matched nothing, which turned the policy gate off.
func (c Config) Validate() error {
	invalid := func(key, format string, args ...any) error {
		return &ErrInvalidConfig{Key: key, Reason: fmt.Sprintf(format, args...)}
	}
	if c.Version != 1 {
		return invalid("version", "unsupported config version %d (this imgowner reads version 1)", c.Version)
	}
	if err := checkPlatform(c.Scan.Platform); err != nil {
		return invalid("scan.platform", "%v", err)
	}
	if err := checkDuration(c.Scan.TimeoutStr); err != nil {
		return invalid("scan.timeout", "%v", err)
	}
	if c.Scan.BaseCandidates < 0 {
		return invalid("scan.base_candidates", "must be 0 (off) or more (got %d)", c.Scan.BaseCandidates)
	}
	if !semverLike(c.Scan.TrivyMinVersion) {
		return invalid("scan.trivy_min_version", "must look like 0.76.0 (got %q)", c.Scan.TrivyMinVersion)
	}
	for _, s := range c.Policy.FailOn {
		if !oneOf(strings.ToUpper(s), severities) {
			return invalid("policy.fail_on", "unknown severity %q (use %s)", s, strings.Join(severities, ", "))
		}
	}
	for _, o := range c.Policy.EnforceOwners {
		if !oneOf(strings.ToLower(o), owners) {
			return invalid("policy.enforce_owners", "unknown owner %q (use %s)", o, strings.Join(owners, ", "))
		}
	}
	if err := checkDuration(c.Pins.LookupTimeout); err != nil {
		return invalid("pins.lookup_timeout", "%v", err)
	}
	if !oneOf(c.Pins.Runtime, runtimes) {
		return invalid("pins.runtime", "unknown runtime %q (use %s)", c.Pins.Runtime, strings.Join(runtimes, ", "))
	}
	for _, f := range c.Report.Formats {
		if !oneOf(strings.ToLower(f), formats) {
			return invalid("report.formats", "unknown format %q (use md, json, sarif)", f)
		}
	}
	if !oneOf(c.SCM.Provider, providers) {
		return invalid("scm.provider", "unknown provider %q (use %s)", c.SCM.Provider, strings.Join(providers, ", "))
	}
	if c.History.RetentionDays < 1 {
		return invalid("history.retention_days", "must be at least 1 (got %d)", c.History.RetentionDays)
	}
	return nil
}

func oneOf(v string, allowed []string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func checkDuration(s string) error {
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("not a duration %q (use e.g. 90s, 10m, 1h)", s)
	}
	if d <= 0 {
		return fmt.Errorf("must be positive (got %s)", s)
	}
	return nil
}

func checkPlatform(p string) error {
	parts := strings.Split(p, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("must be os/arch or os/arch/variant, e.g. linux/amd64 (got %q)", p)
	}
	return nil
}

var semverRe = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)

func semverLike(v string) bool { return semverRe.MatchString(v) }

// Defaults returns a Config populated with built-in defaults.
func Defaults() Config {
	return Config{
		Version: 1,
		Scan: Scan{
			Platform:        "linux/amd64",
			TrivyMinVersion: "0.76.0",
			TimeoutStr:      "10m",
			BaseCandidates:  5,
		},
		Policy: Policy{
			FailOn:        []string{"CRITICAL", "HIGH"},
			EnforceOwners: []string{"app", "added-os"},
			NewOnly:       false,
		},
		Pins: Pins{
			Enabled:       true,
			Runtime:       "auto",
			LookupTimeout: "5m",
			Stages:        "all",
		},
		Report: Report{
			Formats:   []string{"md", "json"},
			OutputDir: "./imgowner-report",
		},
		SCM: SCM{
			Provider:     "auto",
			Comment:      "update",
			BranchPrefix: "fix/os-pins",
		},
		History: History{
			Enabled:       true,
			RetentionDays: 90,
		},
	}
}

// Timeout returns the per-scan ceiling parsed from scan.timeout.
// An unparseable or absent value yields 10m so a bad config cannot turn into
// an unbounded scan.
func (s Scan) Timeout() time.Duration {
	d, err := time.ParseDuration(s.TimeoutStr)
	if err != nil || d <= 0 {
		return 10 * time.Minute
	}
	return d
}

// LookupDuration returns the per-stage container lookup ceiling from pins.lookup_timeout.
func (p Pins) LookupDuration() time.Duration {
	d, err := time.ParseDuration(p.LookupTimeout)
	if err != nil || d <= 0 {
		return 5 * time.Minute
	}
	return d
}

// Load reads the config file at path (if it exists) and merges it over
// defaults. Unknown keys cause an error (FR-29). Use it for the default
// path, which a project need not have; LoadRequired is for a path the user
// named explicitly.
func Load(path string) (Config, error) {
	return load(path, false)
}

// LoadRequired is Load for a config file the user named with --config: a
// missing file is an error, not a silent fall back to defaults (which would
// drop every policy the user thinks is in force).
func LoadRequired(path string) (Config, error) {
	return load(path, true)
}

func load(path string, required bool) (Config, error) {
	cfg := Defaults()

	data, err := safeio.ReadFile(path, safeio.MaxConfig)
	if os.IsNotExist(err) && !required {
		return cfg, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("imgowner: reading config %s: %w", path, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // unknown keys → structured error (FR-29)
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			// An empty (or all-comments) file carries no overrides; that is
			// not a configuration error.
			return cfg, nil
		}
		if uk := unknownKey(err); uk != nil {
			return Config{}, uk
		}
		return Config{}, fmt.Errorf("imgowner: config error in %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// yaml.v3 reports an unknown key as "line N: field X not found in type
// config.T"; sections maps T back to the key's place in the file.
var (
	unknownFieldRe = regexp.MustCompile(`line (\d+): field (\S+) not found in type config\.(\w+)`)
	sections       = map[string]string{
		"Config": "", "Scan": "scan", "Policy": "policy", "Pins": "pins",
		"Report": "report", "SCM": "scm", "History": "history",
	}
)

// unknownKey extracts the first unknown key from a decode error, or nil.
func unknownKey(err error) *ErrUnknownKey {
	m := unknownFieldRe.FindStringSubmatch(err.Error())
	if m == nil {
		return nil
	}
	line, _ := strconv.Atoi(m[1])
	key := m[2]
	if section, ok := sections[m[3]]; ok && section != "" {
		key = section + "." + key
	}
	return &ErrUnknownKey{Key: key, Line: line}
}
