package attribution

import (
	"bytes"
	"errors"
	"iter"
	"os"
	"path/filepath"
	"testing"
)

// goodEntries is a minimal valid entry stream.
func goodEntries(t *testing.T) iter.Seq2[Entry, error] {
	t.Helper()
	return entriesFrom([]Entry{
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Services: []string{"EC2"}}},
	})
}

// TestBuildFileAtomicWritesValidDB confirms a normal build produces a file that
// opens, validates, and looks up.
func TestBuildFileAtomicWritesValidDB(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cloud.mmdb")
	if _, err := BuildFile(goodEntries(t), out, BuildOptions{}, nil, 0); err != nil {
		t.Fatal(err)
	}
	db, err := OpenValidated(out)
	if err != nil {
		t.Fatalf("OpenValidated: %v", err)
	}
	defer db.Close()
	if _, found, _ := db.LookupString("52.94.0.1"); !found {
		t.Error("expected hit")
	}
	// No leftover temp files in the directory.
	ents, _ := os.ReadDir(filepath.Dir(out))
	for _, e := range ents {
		if e.Name() != "cloud.mmdb" {
			t.Errorf("unexpected leftover file: %s", e.Name())
		}
	}
}

// TestBuildFileLeavesExistingOnError simulates a build that fails partway (an
// entry stream error, like a truncated/aborted source download): the previous
// good database must be left untouched, not clobbered or truncated.
func TestBuildFileLeavesExistingOnError(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cloud.mmdb")
	if _, err := BuildFile(goodEntries(t), out, BuildOptions{}, nil, 0); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	// A stream that yields one entry then errors (e.g. partial feed).
	failing := func(yield func(Entry, error) bool) {
		yield(Entry{Network: mustPrefix(t, "10.1.0.0/16"), Record: Record{Provider: "aws", Services: []string{"X"}}}, nil)
		yield(Entry{}, errors.New("connection reset mid-feed"))
	}
	if _, err := BuildFile(failing, out, BuildOptions{}, nil, 0); err == nil {
		t.Fatal("expected build error from failing stream")
	}

	after, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("existing db disappeared: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("existing database was modified by a failed build")
	}
	// And no temp turds left behind.
	ents, _ := os.ReadDir(filepath.Dir(out))
	if len(ents) != 1 {
		t.Errorf("expected only the original file, got %d entries", len(ents))
	}
}

// TestOpenValidatedRejectsCorrupt covers partial-copy / corruption: truncated,
// empty, and garbage files must be rejected rather than served.
func TestOpenValidatedRejectsCorrupt(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.mmdb")
	if _, err := BuildFile(goodEntries(t), good, BuildOptions{}, nil, 0); err != nil {
		t.Fatal(err)
	}
	full, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty":     {},
		"truncated": full[:len(full)/2], // partial copy: metadata at EOF is gone
		"garbage":   bytes.Repeat([]byte{0xff}, 4096),
		"prefix":    full[:64],
	}
	for name, data := range cases {
		p := filepath.Join(dir, name+".mmdb")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if db, err := OpenValidated(p); err == nil {
			db.Close()
			t.Errorf("%s: OpenValidated accepted a corrupt file", name)
		}
	}
}
