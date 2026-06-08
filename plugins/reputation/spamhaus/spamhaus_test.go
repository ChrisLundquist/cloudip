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
