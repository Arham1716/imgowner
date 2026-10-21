package pins

import "testing"

func TestApplyEdits_Single(t *testing.T) {
	content := []byte("RUN apt-get install -y curl=7.88.1-10\n")
	// "7.88.1-10" starts at index 29 (after "curl=")
	offset := findVersionOffset(content, buildLineOffsets(content), 1, "curl", "7.88.1-10", "apt")

	edits := []Edit{{ByteOffset: offset, OldVersion: "7.88.1-10", NewVersion: "7.88.1-12"}}
	got, err := ApplyEdits(content, edits)
	if err != nil {
		t.Fatalf("ApplyEdits: %v", err)
	}
	want := "RUN apt-get install -y curl=7.88.1-12\n"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestApplyEdits_Multiple(t *testing.T) {
	content := []byte("RUN apt-get install -y curl=7.88.1-10 openssl=3.0.11-1\n")
	lineOff := buildLineOffsets(content)

	offCurl := findVersionOffset(content, lineOff, 1, "curl", "7.88.1-10", "apt")
	offSSL := findVersionOffset(content, lineOff, 1, "openssl", "3.0.11-1", "apt")

	edits := []Edit{
		{ByteOffset: offCurl, OldVersion: "7.88.1-10", NewVersion: "7.88.1-12"},
		{ByteOffset: offSSL, OldVersion: "3.0.11-1", NewVersion: "3.0.11-2"},
	}
	got, err := ApplyEdits(content, edits)
	if err != nil {
		t.Fatalf("ApplyEdits: %v", err)
	}
	want := "RUN apt-get install -y curl=7.88.1-12 openssl=3.0.11-2\n"
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestApplyEdits_Mismatch(t *testing.T) {
	content := []byte("RUN apt-get install -y curl=7.88.1-10\n")
	edits := []Edit{{ByteOffset: 27, OldVersion: "WRONGVER", NewVersion: "9.0"}}
	_, err := ApplyEdits(content, edits)
	if err == nil {
		t.Error("expected error for version mismatch, got nil")
	}
}

func TestPlanEdits(t *testing.T) {
	pinList := []Pin{
		{Package: "curl", Version: "7.88.1-10", Available: "7.88.1-12", ByteOffset: 10, Status: StatusUpdateAvailable},
		{Package: "openssl", Version: "3.0.11-1", Available: "3.0.11-2", ByteOffset: 30, Status: StatusFixesCVEs},
		{Package: "ca-certificates", Version: "20230311", Available: "", ByteOffset: 50, Status: StatusCurrent},
	}
	edits := PlanEdits(pinList)
	if len(edits) != 2 {
		t.Fatalf("expected 2 edits, got %d", len(edits))
	}
}

func TestSortEditsDesc(t *testing.T) {
	edits := []Edit{
		{ByteOffset: 10},
		{ByteOffset: 50},
		{ByteOffset: 30},
	}
	sortEditsDesc(edits)
	if edits[0].ByteOffset != 50 || edits[1].ByteOffset != 30 || edits[2].ByteOffset != 10 {
		t.Errorf("unexpected order: %v", edits)
	}
}
