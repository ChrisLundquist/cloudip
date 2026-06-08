package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func mustParsePrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSplitCSV(t *testing.T) {
	cases := map[string][]string{
		"":            nil,
		"   ":         nil,
		"aws":         {"aws"},
		"aws,gcp":     {"aws", "gcp"},
		" aws , gcp ": {"aws", "gcp"},
		"aws,,gcp,":   {"aws", "gcp"},
		",aws,":       {"aws"},
	}
	for in, want := range cases {
		got := splitCSV(in)
		if len(got) != len(want) {
			t.Errorf("splitCSV(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("splitCSV(%q) = %v, want %v", in, got, want)
				break
			}
		}
	}
}

// writeTinyDB builds a one-network MMDB for CLI tests.
func writeTinyDB(t *testing.T) string {
	t.Helper()
	pre := mustParsePrefix(t, "52.94.0.0/22")
	entries := func(yield func(attribution.Entry, error) bool) {
		yield(attribution.Entry{Network: pre, Record: attribution.Record{Provider: "aws", Region: "us-east-1", Services: []string{"EC2"}}}, nil)
	}
	path := filepath.Join(t.TempDir(), "cloud.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := attribution.Build(entries, f, attribution.BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRunLookupExitCodes verifies a malformed-only batch returns an error
// (non-zero exit) while a plain miss does not.
func TestRunLookupExitCodes(t *testing.T) {
	db := writeTinyDB(t)

	// All inputs malformed -> error.
	if err := runLookup([]string{"--in", db, "not-an-ip"}); err == nil {
		t.Error("expected error when all lookups fail")
	}

	// A miss is a valid answer -> no error. Capture stdout to keep test output clean.
	withStdout(t, func() {
		if err := runLookup([]string{"--in", db, "203.0.113.9"}); err != nil {
			t.Errorf("miss should not be an error: %v", err)
		}
		// A hit -> no error.
		if err := runLookup([]string{"--in", db, "52.94.0.1"}); err != nil {
			t.Errorf("hit should not be an error: %v", err)
		}
	})
}

func withStdout(t *testing.T, fn func()) {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = old }()
	done := make(chan struct{})
	go func() { _, _ = bytes.NewBuffer(nil).ReadFrom(r); close(done) }()
	fn()
	w.Close()
	<-done
}
