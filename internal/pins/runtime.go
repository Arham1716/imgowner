package pins

import (
	"context"
	"errors"
	"os/exec"
)

// ErrNoRuntime is returned when neither docker nor podman is found.
var ErrNoRuntime = errors.New("docker or podman not found in PATH; required for pin lookup (FR-13)")

// Runtime is the container runtime binary name ("docker" or "podman").
type Runtime string

const (
	RuntimeDocker Runtime = "docker"
	RuntimePodman Runtime = "podman"
)

// DetectRuntime finds the first available container runtime in PATH.
// docker is preferred; podman is the fallback.
func DetectRuntime(ctx context.Context) (Runtime, error) {
	for _, name := range []string{"docker", "podman"} {
		if path, err := exec.LookPath(name); err == nil && path != "" {
			return Runtime(name), nil
		}
	}
	return "", ErrNoRuntime
}

// Run executes a container command using the given runtime.
func (r Runtime) Run(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, string(r), args...)
}
