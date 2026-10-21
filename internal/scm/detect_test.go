package scm

import "testing"

// clearSCMEnv removes the ambient CI signals so each test controls its own
// environment deterministically. Without this, these tests would see
// GITHUB_ACTIONS=true for real when run inside this project's own GitHub
// Actions CI, silently masking the branches that are supposed to be tested.
func clearSCMEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("TF_BUILD", "")
}

func TestDetect_GitHubActionsEnvTakesPriority(t *testing.T) {
	clearSCMEnv(t)
	t.Setenv("GITHUB_ACTIONS", "true")
	// Even an explicit, contradictory config value must lose to the live
	// environment signal: the env reflects where the process is actually
	// running right now, which is more trustworthy than a static config file.
	got, err := Detect("azure-devops")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got != ProviderGitHub {
		t.Errorf("want ProviderGitHub when GITHUB_ACTIONS=true, got %v", got)
	}
}

func TestDetect_AzureDevOpsEnvTakesPriority(t *testing.T) {
	clearSCMEnv(t)
	t.Setenv("TF_BUILD", "true")
	got, err := Detect("github")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got != ProviderAzureDevOps {
		t.Errorf("want ProviderAzureDevOps when TF_BUILD=true, got %v", got)
	}
}

func TestDetect_FallsBackToConfigWhenNoEnvSignal(t *testing.T) {
	clearSCMEnv(t)
	cases := []struct {
		config string
		want   Provider
	}{
		{"github", ProviderGitHub},
		{"azure-devops", ProviderAzureDevOps},
	}
	for _, tc := range cases {
		got, err := Detect(tc.config)
		if err != nil {
			t.Fatalf("Detect(%q): %v", tc.config, err)
		}
		if got != tc.want {
			t.Errorf("Detect(%q) = %v, want %v", tc.config, got, tc.want)
		}
	}
}

func TestDetect_AutoWithNoEnvSignalErrors(t *testing.T) {
	clearSCMEnv(t)
	_, err := Detect("auto")
	if err == nil {
		t.Error("Detect(\"auto\") with no CI env signal should error, not guess a provider")
	}
}

func TestDetect_EmptyConfigErrors(t *testing.T) {
	clearSCMEnv(t)
	_, err := Detect("")
	if err == nil {
		t.Error("Detect(\"\") with no CI env signal should error, not guess a provider")
	}
}

func TestDetect_UnknownConfigValueErrors(t *testing.T) {
	clearSCMEnv(t)
	_, err := Detect("gitlab")
	if err == nil {
		t.Error("Detect(\"gitlab\") should error: gitlab is not a supported scm.provider value")
	}
}
