package attribution

import (
	"context"
	"io"
	"iter"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// testPlugin yields one entry per non-empty line "cidr service" in the ref.
type testPlugin struct {
	name string
	refs []string
}

func (p testPlugin) Name() string   { return p.name }
func (p testPlugin) Refs() []string { return p.refs }

func (p testPlugin) Parse(ref string, r io.Reader) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		data, err := io.ReadAll(r)
		if err != nil {
			yield(Entry{}, err)
			return
		}
		for _, line := range splitLines(string(data)) {
			cidr, svc, _ := cut(line, ' ')
			pre, err := netip.ParsePrefix(cidr)
			if err != nil {
				if !yield(Entry{}, err) {
					return
				}
				continue
			}
			if !yield(Entry{Network: pre, Record: Record{Provider: p.name, Services: []string{svc}, Source: ref}}, nil) {
				return
			}
		}
	}
}

func TestCollectFixtureResolver(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.txt"), []byte("192.0.2.0/24 EC2\n198.51.100.0/24 S3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := testPlugin{name: "demo", refs: []string{"p.txt"}}

	var got []Entry
	for e, err := range Collect(context.Background(), []Plugin{p}, FixtureResolver(dir)) {
		if err != nil {
			t.Fatalf("collect error: %v", err)
		}
		got = append(got, e)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].Record.Provider != "demo" || got[0].Record.Source != "p.txt" {
		t.Errorf("entry = %+v", got[0])
	}
}

func TestCollectOpenErrorIsReported(t *testing.T) {
	p := testPlugin{name: "demo", refs: []string{"missing.txt"}}
	var sawErr bool
	for _, err := range Collect(context.Background(), []Plugin{p}, FixtureResolver(t.TempDir())) {
		if err != nil {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatal("expected an open error for a missing fixture")
	}
}

func TestRefsForDirectFallback(t *testing.T) {
	// A plugin without DirectPlugin falls back to its rezmoss refs in direct mode.
	p := testPlugin{name: "demo", refs: []string{"demo/file.json"}}
	if got := RefsFor(p, true); len(got) != 1 || got[0] != "demo/file.json" {
		t.Errorf("RefsFor(direct) = %v, want rezmoss fallback", got)
	}
}

// tiny string helpers to keep the test dependency-free.
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if line := s[start:i]; line != "" {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	if line := s[start:]; line != "" {
		out = append(out, line)
	}
	return out
}

func cut(s string, sep byte) (before, after string, found bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
