package attribution

import (
	"bytes"
	"errors"
	"fmt"
	"iter"
	"net/netip"
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
	if _, err := BuildFile(goodEntries(t), out, BuildOptions{}, nil, 0, 0); err != nil {
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
	if _, err := BuildFile(goodEntries(t), out, BuildOptions{}, nil, 0, 0); err != nil {
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
	if _, err := BuildFile(failing, out, BuildOptions{}, nil, 0, 0); err == nil {
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

// manyEntries yields n distinct /24 networks for the given provider, each with a
// unique region so mmdbwriter does NOT collapse adjacent identical records into
// aggregates (which would make the post-walk network count unpredictable).
func manyEntries(provider string, n int) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		for i := 0; i < n; i++ {
			p := netip.PrefixFrom(netip.AddrFrom4([4]byte{100, byte(i / 256), byte(i % 256), 0}), 24)
			rec := Record{Provider: provider, Region: fmt.Sprintf("r%d", i), Services: []string{"S"}}
			if !yield(Entry{Network: p, Record: rec}, nil) {
				return
			}
		}
	}
}

// TestBuildFileDropGuard covers the production safety gate: a build that shrinks
// more than maxDropFrac vs the previous database must be refused, leaving the old
// file intact; a build within the threshold must publish.
func TestBuildFileDropGuard(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cloud.mmdb")

	// Seed with 100 networks.
	first, err := BuildFile(manyEntries("aws", 100), out, BuildOptions{}, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.Report.Networks != 100 {
		t.Fatalf("seed networks = %d, want 100", first.Report.Networks)
	}
	seedBytes, _ := os.ReadFile(out)

	// A build dropping to 40 networks (60% drop) with a 50% guard must be refused.
	prev := first.Report
	if _, err := BuildFile(manyEntries("aws", 40), out, BuildOptions{}, &prev, 0.5, 0); err == nil {
		t.Error("expected drop-guard to refuse a 60% drop")
	}
	after, _ := os.ReadFile(out)
	if !bytes.Equal(seedBytes, after) {
		t.Error("refused build still modified the published file")
	}

	// A build to 60 networks (40% drop) is within the 50% guard and must publish.
	res, err := BuildFile(manyEntries("aws", 60), out, BuildOptions{}, &prev, 0.5, 0)
	if err != nil {
		t.Fatalf("within-threshold build refused: %v", err)
	}
	if res.Report.Networks != 60 {
		t.Errorf("published networks = %d, want 60", res.Report.Networks)
	}
}

// TestBuildFileSkipGuard covers the skip-ratio gate: a feed where most entries
// are skipped (here, aliased ranges) must be refused even on a first build.
func TestBuildFileSkipGuard(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cloud.mmdb")
	// 1 good network + 4 aliased (skipped) => 80% skip ratio.
	mixed := func(yield func(Entry, error) bool) {
		yield(Entry{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Services: []string{"EC2"}}}, nil)
		for i := 0; i < 4; i++ {
			yield(Entry{Network: mustPrefix(t, "2002::/16"), Record: Record{Provider: "x", Services: []string{"y"}}}, nil)
		}
	}
	if _, err := BuildFile(mixed, out, BuildOptions{}, nil, 0, 0.25); err == nil {
		t.Error("expected skip-guard to refuse an 80% skip ratio")
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("refused build should not have published a file")
	}
}

// TestNetworksEarlyStop covers the iterator's consumer-stops branch.
func TestNetworksEarlyStop(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Build(manyEntries("aws", 50), &buf, BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	db, err := OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seen := 0
	for range db.Networks() {
		seen++
		if seen == 3 {
			break // stop early; the iterator must honor it without panicking
		}
	}
	if seen != 3 {
		t.Errorf("iterated %d networks, want early stop at 3", seen)
	}
}

// TestOpenValidatedRejectsCorrupt covers partial-copy / corruption: truncated,
// empty, and garbage files must be rejected rather than served.
func TestOpenValidatedRejectsCorrupt(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.mmdb")
	if _, err := BuildFile(goodEntries(t), good, BuildOptions{}, nil, 0, 0); err != nil {
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
