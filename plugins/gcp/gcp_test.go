package gcp

import (
	"os"
	"strings"
	"testing"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func TestParse(t *testing.T) {
	f, err := os.Open("testdata/cloud.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var entries []attribution.Entry
	for e, err := range (Plugin{}).Parse("gcp/cloud.json", f) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		entries = append(entries, e)
	}

	if got, want := len(entries), 3; got != want {
		t.Fatalf("got %d entries, want %d", got, want)
	}

	var sawV6 bool
	for _, e := range entries {
		if e.Record.Provider != "gcp" {
			t.Errorf("provider = %q", e.Record.Provider)
		}
		if e.Record.Region == "" {
			t.Errorf("expected scope mapped to region for %s", e.Network)
		}
		if e.Network.Addr().Is6() {
			sawV6 = true
		}
	}
	if !sawV6 {
		t.Error("expected an IPv6 prefix from ipv6Prefix field")
	}
	if entries[0].Record.SyncedAt.IsZero() {
		t.Error("creationTime not parsed")
	}
}

// TestParseGlobalScope checks scope:"global" is normalized to an empty region,
// matching the rezmoss path so --source direct and --source rezmoss agree.
func TestParseGlobalScope(t *testing.T) {
	const doc = `{"creationTime":"2024-06-07T20:53:14.000000","prefixes":[
	  {"ipv4Prefix":"34.96.0.0/16","service":"Google Cloud","scope":"global"},
	  {"ipv4Prefix":"34.80.0.0/15","service":"Google Cloud","scope":"asia-east1"}
	]}`
	var got []attribution.Entry
	for e, err := range (Plugin{}).Parse("gcp/cloud.json", strings.NewReader(doc)) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, e)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries", len(got))
	}
	if got[0].Record.Region != "" {
		t.Errorf("global scope = %q, want empty region", got[0].Record.Region)
	}
	if got[1].Record.Region != "asia-east1" {
		t.Errorf("region = %q, want asia-east1", got[1].Record.Region)
	}
}
