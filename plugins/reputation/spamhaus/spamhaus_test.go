package spamhaus

import (
	"os"
	"strings"
	"testing"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func TestParse(t *testing.T) {
	f, err := os.Open("testdata/drop.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var entries []attribution.Entry
	for e, err := range (Plugin{}).Parse("spamhaus/drop.txt", f) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		entries = append(entries, e)
	}
	// 3 CIDR lines; the 4 ";"-comment header lines are skipped.
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}

	e := entries[0]
	if e.Network.String() != "1.10.16.0/20" {
		t.Errorf("network = %s", e.Network)
	}
	if e.Record.Provider != "spamhaus" {
		t.Errorf("provider = %q", e.Record.Provider)
	}
	if strings.Join(e.Record.Categories, ",") != "drop,hijacked" {
		t.Errorf("categories = %v", e.Record.Categories)
	}
	if e.Record.Ext["sbl"] != "SBL256894" {
		t.Errorf("sbl = %q", e.Record.Ext["sbl"])
	}
}

func TestRegistered(t *testing.T) {
	if _, ok := attribution.ReputationPlugins()["spamhaus"]; !ok {
		t.Error("spamhaus not registered")
	}
}

// TestParseEdgeCases covers a no-";" CIDR line, the trailing "; EOF" marker the
// live feed ends with, blank lines, and CRLF endings.
func TestParseEdgeCases(t *testing.T) {
	const feed = "; header (c) Spamhaus\r\n" +
		"1.10.16.0/20 ; SBL256894\r\n" +
		"\r\n" +
		"203.0.113.0/24\r\n" + // no SBL reference
		"; EOF\r\n"
	var entries []attribution.Entry
	for e, err := range (Plugin{}).Parse("spamhaus/drop.txt", strings.NewReader(feed)) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	// The no-";" line parses with an empty SBL.
	last := entries[1]
	if last.Network.String() != "203.0.113.0/24" {
		t.Errorf("network = %s", last.Network)
	}
	if last.Record.Ext["sbl"] != "" {
		t.Errorf("expected no sbl, got %q", last.Record.Ext["sbl"])
	}
}
