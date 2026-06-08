package feodo

import (
	"os"
	"strings"
	"testing"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func TestParse(t *testing.T) {
	f, err := os.Open("testdata/ipblocklist.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var entries []attribution.Entry
	for e, err := range (Plugin{}).Parse("feodo/ipblocklist.json", f) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	e := entries[0]
	if e.Network.String() != "162.243.103.246/32" {
		t.Errorf("network = %s, want /32 host", e.Network)
	}
	if e.Record.Provider != "abuse.ch" {
		t.Errorf("provider = %q", e.Record.Provider)
	}
	if strings.Join(e.Record.Categories, ",") != "botnet_c2,malware" {
		t.Errorf("categories = %v", e.Record.Categories)
	}
	if e.Record.Ext["malware"] != "Emotet" {
		t.Errorf("ext malware = %q", e.Record.Ext["malware"])
	}
	if e.Record.SyncedAt.IsZero() {
		t.Error("first_seen not parsed")
	}
	// Reputation records carry no services.
	if len(e.Record.Services) != 0 {
		t.Errorf("unexpected services: %v", e.Record.Services)
	}
}

func TestRegistered(t *testing.T) {
	if _, ok := attribution.ReputationPlugins()["feodo"]; !ok {
		t.Error("feodo not registered in reputation registry")
	}
	if _, ok := attribution.Plugins()["feodo"]; ok {
		t.Error("feodo should NOT be in the cloud registry")
	}
}

func TestParseBadJSON(t *testing.T) {
	var sawErr bool
	for _, err := range (Plugin{}).Parse("x", strings.NewReader("{not json")) {
		if err != nil {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatal("expected parse error")
	}
}
