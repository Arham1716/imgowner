package pins

// Status is the classification of a pinned OS package (FR-16).
type Status string

const (
	StatusCurrent         Status = "current"           // pinned == latest available
	StatusUpdateAvailable Status = "update-available"  // newer version exists
	StatusFixesCVEs       Status = "fixes-CVE(s)"      // newer version resolves attributed CVEs
	StatusUnavailable     Status = "unavailable"       // pinned version absent from repo
	StatusUnknown         Status = "unknown"            // lookup timed out or output unparseable
	StatusVariable        Status = "variable"           // version is ARG-only, no default
	StatusUnsupported     Status = "unsupported"        // package from a third-party repo
)

// Pin is one exact-pinned OS package extracted from a Dockerfile RUN instruction.
type Pin struct {
	Stage      string // Dockerfile stage name or index
	Package    string // package name, e.g. "curl"
	Version    string // pinned version, e.g. "7.88.1-10"
	Available  string // latest version from repo lookup (empty until lookup runs)
	Line       int    // 1-based Dockerfile line number
	ByteOffset int    // byte offset of the version string within the Dockerfile
	Manager    string // "apt" or "apk"
	Status     Status
	FixesCVEs  []string // CVE IDs fixed by upgrading (populated by compare step)
}
