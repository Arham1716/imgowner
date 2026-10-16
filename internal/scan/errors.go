package scan

import "fmt"

// ErrToolMissing is returned when a required external tool is not found.
type ErrToolMissing struct {
	Tool string
	Hint string
}

func (e *ErrToolMissing) Error() string {
	return fmt.Sprintf("imgowner: %s not found: %s", e.Tool, e.Hint)
}

// ErrVersionTooOld is returned when an installed tool is below the minimum version.
type ErrVersionTooOld struct {
	Tool     string
	Found    string
	Required string
}

func (e *ErrVersionTooOld) Error() string {
	return fmt.Sprintf("imgowner: %s version too old: found %s, required %s", e.Tool, e.Found, e.Required)
}
