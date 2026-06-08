package tor

import (
	"os"
	"strings"
	"testing"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func TestParse(t *testing.T) {
	f, err := os.Open("testdata/exit-list.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var entries []attribution.Entry
	for e, err := range (Plugin{}).Parse("tor/exit-list.txt", f) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	e := entries[0]
	if e.Network.String() != "171.25.193.25/32" {
		t.Errorf("network = %s, want /32 host", e.Network)
	}
	if e.Record.Provider != "tor" {
		t.Errorf("provider = %q", e.Record.Provider)
	}
	if strings.Join(e.Record.Categories, ",") != "tor_exit,anonymizer" {
		t.Errorf("categories = %v", e.Record.Categories)
	}
}

func TestRegistered(t *testing.T) {
	if _, ok := attribution.ReputationPlugins()["tor"]; !ok {
		t.Error("tor not registered")
	}
}
