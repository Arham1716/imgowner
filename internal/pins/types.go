package pins

// Status is the classification of a pinned OS package (FR-16).
type Status string

const (
	StatusCurrent         Status = "current"          // pinned == latest available
	StatusUpdateAvailable Status = "update-available" // newer version exists
	StatusFixesCVEs       Status = "fixes-CVE(s)"     // newer version resolves attributed CVEs
	StatusUnavailable     Status = "unavailable"      // pinned version absent from repo
	StatusUnknown         Status = "unknown"          // lookup timed out or output unparseable
	StatusVariable        Status = "variable"         // version is ARG-only, no default
	StatusUnsupported     Status = "unsupported"      // package from a third-party repo
)

// Pin is one exact-pinned OS package extracted from a Dockerfile RUN instruction.
type Pin struct {
	Stage      string   `json:"stage"`               // Dockerfile stage name ("" when unnamed)
	StageIndex int      `json:"stage_index"`         // 0-based stage index; groups pins for lookup (FR-15)
	Package    string   `json:"package"`             // package name, e.g. "curl"
	Version    string   `json:"version"`             // pinned version, e.g. "7.88.1-10"
	Available  string   `json:"available,omitempty"` // latest version from repo lookup (empty until lookup runs)
	Line       int      `json:"line"`                // 1-based Dockerfile line number
	ByteOffset int      `json:"byte_offset"`         // byte offset of the version string within the Dockerfile
	Manager    string   `json:"manager"`             // "apt", "apk", or "rpm"
	Status     Status   `json:"status"`
	FixesCVEs  []string `json:"fixes_cves,omitempty"` // CVE IDs fixed by upgrading (populated by compare step)
	Note       string   `json:"note,omitempty"`       // why the status is what it is (variable, unsupported, ARG source)
}

// Lookupable reports whether a pin's versions can be queried from the
// stage's OS repository: variable and unsupported pins can't, and must keep
// their status rather than have a lookup overwrite it.
func (p Pin) Lookupable() bool {
	return p.Status != StatusVariable && p.Status != StatusUnsupported
}
