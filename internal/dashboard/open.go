package dashboard

import (
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
)

// OpenBrowser opens rawURL in the user's default browser. The binary and its
// arguments are fixed per platform; the only variable part is the URL, which
// must be the loopback URL this package built, so nothing a request, a config
// file or the environment supplies can reach the command line.
func OpenBrowser(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" {
		return errors.New("dashboard: refusing to open a non-loopback URL")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// "start" is a cmd builtin and would re-parse the URL as shell text;
		// rundll32 takes it as a single argument.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL) // #nosec G204 -- fixed binary, validated loopback URL
	case "darwin":
		cmd = exec.Command("open", rawURL) // #nosec G204 -- fixed binary, validated loopback URL
	default:
		cmd = exec.Command("xdg-open", rawURL) // #nosec G204 -- fixed binary, validated loopback URL
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("dashboard: opening a browser: %w", err)
	}
	// Reap the helper so it doesn't linger as a zombie; its exit status is
	// irrelevant (the URL is also printed for the user).
	go func() { _ = cmd.Wait() }()
	return nil
}
