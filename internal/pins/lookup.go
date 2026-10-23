package pins

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Arham1716/imgowner/internal/safeio"
)

const lookupTimeout = 5 * time.Minute

// LookupVersions runs one container per stage to query the available versions
// of all pinned packages in that stage (FR-14, FR-15).
// It populates Pin.Available and sets Status to StatusUnavailable if the
// package is absent from the repo.
func LookupVersions(ctx context.Context, rt Runtime, imageRef string, pins []Pin) ([]Pin, error) {
	if len(pins) == 0 {
		return pins, nil
	}

	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	// Determine package manager from the first pin (all pins in a stage share one manager).
	mgr := pins[0].Manager

	script, err := buildLookupScript(mgr, pins)
	if err != nil {
		return pins, fmt.Errorf("pins: building lookup script for %s: %w", mgr, err)
	}

	cmd := rt.Run(ctx, "run", "--rm", "--entrypoint", "sh", imageRef, "-c", script)
	out, err := safeio.Output(cmd, safeio.MaxLookupOutput, "pin lookup output")
	if err != nil {
		// Non-fatal (design F16 DEFER path): every pin becomes unknown, but the
		// caller gets the reason so it can be reported instead of leaving the
		// user with a column of "unknown" and no explanation.
		for i := range pins {
			pins[i].Status = StatusUnknown
		}
		return pins, &LookupFailedError{Image: imageRef, Runtime: string(rt), Detail: runFailureDetail(err)}
	}

	return parseLookupOutput(out, pins), nil
}

// LookupFailedError reports that the container version lookup for one stage
// could not run. The pins it covers are still returned, marked unknown, so
// callers should treat this as a warning rather than abort.
type LookupFailedError struct {
	Image   string
	Runtime string
	Detail  string
}

func (e *LookupFailedError) Error() string {
	return fmt.Sprintf("pin version lookup in %s via %s failed: %s", e.Image, e.Runtime, e.Detail)
}

// runFailureDetail extracts the runtime's own stderr, which carries the useful
// part ("failed to connect to the docker API ..." when the daemon is down);
// the Go error alone is just "exit status 1".
func runFailureDetail(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(bytes.TrimSpace(ee.Stderr)) > 0 {
		msg := strings.TrimSpace(string(ee.Stderr))
		if len(msg) > 500 {
			msg = msg[:500] + "… (truncated)"
		}
		return msg
	}
	return err.Error()
}

// buildLookupScript produces a shell script that outputs one line per package:
//
//	CURRENT|<pkg>|<pinned>|<latest>
//	UPDATE|<pkg>|<pinned>|<latest>
//	UNAVAILABLE|<pkg>
//
// FR-15: batched into a single container run per stage.
func buildLookupScript(mgr string, pins []Pin) (string, error) {
	var b strings.Builder

	switch mgr {
	case "apt":
		b.WriteString("apt-get update -qq 2>/dev/null; ")
		for _, p := range pins {
			// Escape package name for shell safety (packages can contain letters, digits, +, -, .).
			pkg := sanitizeIdentifier(p.Package)
			pin := sanitizeVersion(p.Version)
			fmt.Fprintf(&b,
				`LATEST=$(apt-cache madison %s 2>/dev/null | awk -F'|' 'NR==1{gsub(/ /,"",$2);print $2}'); `+
					`if [ -z "$LATEST" ]; then echo "UNAVAILABLE|%s"; `+
					`elif dpkg --compare-versions "$LATEST" gt "%s" 2>/dev/null; then echo "UPDATE|%s|%s|$LATEST"; `+
					`else echo "CURRENT|%s|%s|$LATEST"; fi; `,
				pkg, pkg, pin, pkg, pin, pkg, pin,
			)
		}

	case "apk":
		b.WriteString("apk update -q 2>/dev/null; ")
		for _, p := range pins {
			pkg := sanitizeIdentifier(p.Package)
			pin := sanitizeVersion(p.Version)
			// apk search returns "pkgname-version"; strip the prefix to get version.
			fmt.Fprintf(&b,
				`LATEST=$(apk search -q "^%s" 2>/dev/null | grep "^%s-[0-9]" | sort -V | tail -1 | sed "s/^%s-//"); `+
					`if [ -z "$LATEST" ]; then echo "UNAVAILABLE|%s"; `+
					`elif apk version -t "$LATEST" "%s" 2>/dev/null | grep -q ">"; then echo "UPDATE|%s|%s|$LATEST"; `+
					`else echo "CURRENT|%s|%s|$LATEST"; fi; `,
				pkg, pkg, pkg, pkg, pin, pkg, pin, pkg, pin,
			)
		}

	case "rpm":
		// dnf and yum share this query surface; microdnf images usually ship
		// neither, so fall back through whichever binary exists.
		b.WriteString(`PM=$(command -v dnf || command -v yum || command -v microdnf); `)
		for _, p := range pins {
			pkg := sanitizeIdentifier(p.Package)
			pin := sanitizeVersion(p.Version)
			// "dnf list available" prints "name.arch  version-release  repo";
			// take the newest version column for this exact package name.
			fmt.Fprintf(&b,
				`LATEST=$($PM -q list available %s 2>/dev/null | awk '$1 ~ /^%s\./ {print $2}' | sort -V | tail -1); `+
					`if [ -z "$LATEST" ]; then echo "UNAVAILABLE|%s"; `+
					`elif [ "$LATEST" != "%s" ]; then echo "UPDATE|%s|%s|$LATEST"; `+
					`else echo "CURRENT|%s|%s|$LATEST"; fi; `,
				pkg, pkg, pkg, pin, pkg, pin, pkg, pin,
			)
		}

	default:
		return "", fmt.Errorf("unsupported package manager %q", mgr)
	}

	return b.String(), nil
}

// parseLookupOutput reads the container script's stdout and updates pin statuses.
func parseLookupOutput(out []byte, pins []Pin) []Pin {
	// Build a lookup map by package name for O(1) updates.
	byPkg := make(map[string]*Pin, len(pins))
	for i := range pins {
		byPkg[pins[i].Package] = &pins[i]
	}

	for _, line := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
		// '|' delimits fields because it can't occur in a package name or
		// version, whereas ':' can (Debian epochs such as "1:2024b-0").
		parts := strings.SplitN(string(line), "|", 4)
		if len(parts) < 2 {
			continue
		}
		kind, pkg := parts[0], parts[1]
		p, ok := byPkg[pkg]
		if !ok {
			continue
		}

		switch kind {
		case "UNAVAILABLE":
			p.Status = StatusUnavailable
		case "CURRENT", "UPDATE":
			// The version comes from a container built on an image we don't
			// control, and PlanEdits/ApplyEdits write it verbatim into the
			// Dockerfile of an auto-opened PR. Anything that isn't a plain
			// version string (shell metacharacters, whitespace, newlines) could
			// inject instructions into that Dockerfile, so it is rejected and
			// the pin stays unknown rather than trusting it.
			if len(parts) != 4 || !isPlainVersion(parts[3]) {
				continue
			}
			p.Available = parts[3]
			if kind == "CURRENT" {
				p.Status = StatusCurrent
			} else {
				p.Status = StatusUpdateAvailable
			}
		}
	}

	// Any pin not updated by the output stays StatusUnknown.
	return pins
}

// sanitizeIdentifier allows only characters valid in apt/apk package names.
func sanitizeIdentifier(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '+' || r == '.' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isPlainVersion reports whether s is non-empty and made only of characters
// valid in a Debian/Alpine/RPM version string.
func isPlainVersion(s string) bool {
	return s != "" && len(s) <= 256 && sanitizeVersion(s) == s
}

// sanitizeVersion allows only characters valid in Debian/Alpine version strings.
func sanitizeVersion(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '-' || r == '+' || r == ':' || r == '~' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
