package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
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

// Validate checks values that are structurally valid YAML but semantically
// unusable.
func (c Config) Validate() error {
	if c.History.RetentionDays < 1 {
		return &ErrInvalidConfig{
			Key:    "history.retention_days",
			Reason: fmt.Sprintf("must be at least 1 (got %d)", c.History.RetentionDays),
		}
	}
	return nil
}

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
// defaults. Unknown keys cause an error (FR-29).
func Load(path string) (Config, error) {
	cfg := Defaults()

	data, err := safeio.ReadFile(path, safeio.MaxConfig)
	if os.IsNotExist(err) {
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
		return Config{}, fmt.Errorf("imgowner: config error in %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
