// Package safeio bounds every read of untrusted input (NFR-13). A Dockerfile,
// a Trivy report, a registry or SCM response, or a container's stdout can all
// be made arbitrarily large by whoever controls them; reading one with no
// ceiling lets that party exhaust the machine's memory. Every such read goes
// through this package so the limit is explicit at the call site.
package safeio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// Limits for each kind of untrusted input. Generous enough that no real input
// comes near them, small enough that a hostile one can't exhaust memory.
const (
	MaxDockerfile   = 4 << 20   // 4 MiB; real Dockerfiles are kilobytes
	MaxConfig       = 1 << 20   // 1 MiB for .imgowner.yaml
	MaxTrivyReport  = 512 << 20 // 512 MiB; a large image's JSON report is tens of MiB
	MaxToolOutput   = 1 << 20   // 1 MiB for short command output such as `trivy version`
	MaxLookupOutput = 16 << 20  // 16 MiB for pin lookup container stdout
	MaxHTTPBody     = 16 << 20  // 16 MiB for SCM API responses
)

// TooLargeError reports that an input exceeded its limit.
type TooLargeError struct {
	What  string
	Limit int64
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("%s exceeds the %d byte limit", e.What, e.Limit)
}

// IsTooLarge reports whether err is, or wraps, a *TooLargeError.
func IsTooLarge(err error) bool {
	var tl *TooLargeError
	return errors.As(err, &tl)
}

// ReadAll reads r until EOF, failing with *TooLargeError instead of reading
// past limit bytes.
func ReadAll(r io.Reader, limit int64, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &TooLargeError{What: what, Limit: limit}
	}
	return data, nil
}

// ReadFile reads the file at path, failing with *TooLargeError if it is larger
// than limit. The size is enforced on the bytes actually read, not on a Stat
// result, so a file that grows between stat and read can't slip past it.
// os.IsNotExist works on the returned error as it does for os.ReadFile.
func ReadFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- reading user-named input files is this tool's job; size is bounded below
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ReadAll(f, limit, path)
}

// Output runs cmd and returns its stdout, like (*exec.Cmd).Output, but kills
// the process and fails with *TooLargeError once stdout passes limit bytes.
// On a non-zero exit the returned error is an *exec.ExitError with Stderr set
// (capped at 64 KiB), matching Output's contract so callers can keep reading
// ExitError.Stderr for diagnostics.
func Output(cmd *exec.Cmd, limit int64, what string) ([]byte, error) {
	if cmd.Stdout != nil || cmd.Stderr != nil {
		return nil, errors.New("safeio: Output requires Stdout and Stderr to be unset")
	}
	stdout := &capWriter{limit: limit}
	stderr := &capWriter{limit: 64 << 10, truncate: true}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if stdout.exceeded {
		return nil, &TooLargeError{What: what, Limit: limit}
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			ee.Stderr = stderr.buf.Bytes()
		}
		return nil, err
	}
	return stdout.buf.Bytes(), nil
}

// capWriter buffers up to limit bytes. Past the limit it either keeps quietly
// discarding (truncate, used for stderr diagnostics) or returns an error,
// which makes os/exec stop copying and the child die on a broken pipe.
type capWriter struct {
	buf      bytes.Buffer
	limit    int64
	truncate bool
	exceeded bool
}

var errCapExceeded = errors.New("safeio: output limit exceeded")

func (w *capWriter) Write(p []byte) (int, error) {
	room := w.limit - int64(w.buf.Len())
	if int64(len(p)) <= room {
		return w.buf.Write(p)
	}
	if room > 0 {
		w.buf.Write(p[:room])
	}
	if w.truncate {
		return len(p), nil
	}
	w.exceeded = true
	return 0, errCapExceeded
}
