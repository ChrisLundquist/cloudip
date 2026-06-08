package aws

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func TestParse(t *testing.T) {
	f, err := os.Open("testdata/ip-ranges.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var entries []attribution.Entry
	for e, err := range (Plugin{}).Parse("aws/ip-ranges.json", f) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		entries = append(entries, e)
	}

	// 4 v4 prefixes + 1 v6 prefix = 5 entries (merging happens in the builder).
	if got, want := len(entries), 5; got != want {
		t.Fatalf("got %d entries, want %d", got, want)
	}

	first := entries[0]
	if first.Record.Provider != "aws" {
		t.Errorf("provider = %q, want aws", first.Record.Provider)
	}
	if first.Record.Region != "us-east-1" {
		t.Errorf("region = %q, want us-east-1", first.Record.Region)
	}
	if first.Record.Source != "aws/ip-ranges.json" {
		t.Errorf("source = %q", first.Record.Source)
	}
	if first.Record.Ext["network_border_group"] != "us-east-1" {
		t.Errorf("ext nbg = %q", first.Record.Ext["network_border_group"])
	}
	want, _ := time.Parse("2006-01-02-15-04-05", "2024-06-10-12-00-00")
	if !first.Record.SyncedAt.Equal(want) {
		t.Errorf("synced_at = %v, want %v", first.Record.SyncedAt, want)
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
		t.Fatal("expected a parse error for malformed JSON")
	}
}
