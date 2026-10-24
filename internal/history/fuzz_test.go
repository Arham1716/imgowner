package history

import (
	"strings"
	"testing"
)

// FuzzDecodeRecord feeds arbitrary bytes to the one place stored record
// bytes become values (FR-46). The store directory is user-writable, so its
// contents are untrusted input to the dashboard: decoding must never panic
// or hang, and anything it accepts must be safe to summarise.
func FuzzDecodeRecord(f *testing.F) {
	seeds := []string{
		`{"summary":{"id":"20260101T000000.000000000Z-deadbeef","counts":{"base":1}},"schema_version":1,"findings":[]}`,
		`{"summary":{},"schema_version":1,"findings":[{"cve":"CVE-1","owner":"base","layer_index":0}]}`,
		`{"summary":null,"schema_version":1,"findings":null,"pins":[{"package":"curl","status":"current"}]}`,
		`{"schema_version":2}`,
		`[]`, `null`, `{`, ``,
		strings.Repeat(`{"a":`, 200) + `1` + strings.Repeat(`}`, 200),
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := DecodeRecord(data)
		if err != nil {
			return
		}
		// Whatever was accepted must be re-summarisable without panicking.
		_ = NewRecord(Input{Findings: rec.Findings, Pins: rec.Pins})
	})
}

// FuzzDecodeSummary covers the partial reader List runs over every file in
// the store.
func FuzzDecodeSummary(f *testing.F) {
	f.Add(`{"summary":{"id":"x","counts":{}}}`)
	f.Add(`{"findings":[]}`)
	f.Add(`{"summary":`)
	f.Add(`"str"`)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = decodeSummary(strings.NewReader(s), "")
	})
}
