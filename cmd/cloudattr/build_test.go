package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChrisLundquist/cloudip/attribution"
)

// TestRunBuildRezmossAllFixture drives runBuild end-to-end through the
// rezmoss-all path against a local all_providers.json fixture, and checks the
// CSV side-export is produced atomically (no leftover temp files).
func TestRunBuildRezmossAllFixture(t *testing.T) {
	dir := t.TempDir()
	feeds := filepath.Join(dir, "feeds")
	if err := os.MkdirAll(filepath.Join(feeds, "all_providers"), 0o755); err != nil {
		t.Fatal(err)
	}
	all := `[
	  {"cidr":"52.94.0.0/22","ip_version":"IPv4","provider":"aws","service":"EC2","region":"us-east-1","last_updated":"2026-06-08 03:23:35"},
	  {"cidr":"173.245.48.0/20","ip_version":"IPv4","provider":"cloudflare","service":"","region":"","last_updated":"2026-06-08 03:23:35"},
	  {"cidr":"170.114.0.0/16","ip_version":"IPv4","provider":"zoom","service":"zoom","region":"GLOBAL","last_updated":"2026-06-08 03:23:35"}
	]`
	if err := os.WriteFile(filepath.Join(feeds, "all_providers", "all_providers.json"), []byte(all), 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "cloud.mmdb")
	csv := filepath.Join(dir, "cloud.csv")
	err := runBuild([]string{
		"--source", "rezmoss-all", "--fixtures", feeds,
		"--out", out, "--csv", csv,
	})
	if err != nil {
		t.Fatalf("runBuild: %v", err)
	}

	db, err := attribution.OpenValidated(out)
	if err != nil {
		t.Fatalf("OpenValidated: %v", err)
	}
	defer db.Close()

	for ip, wantProvider := range map[string]string{
		"52.94.0.1":    "aws",
		"173.245.48.1": "cloudflare",
		"170.114.0.1":  "zoom",
	} {
		rec, found, err := db.LookupString(ip)
		if err != nil || !found {
			t.Errorf("%s: found=%v err=%v", ip, found, err)
			continue
		}
		if rec.Provider != wantProvider {
			t.Errorf("%s -> %q, want %q", ip, rec.Provider, wantProvider)
		}
	}

	// CSV exists and contains a header + rows; no leftover temp files.
	data, err := os.ReadFile(csv)
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if !strings.Contains(string(data), "network_cidr,start_ip_int,end_ip_int") {
		t.Error("csv missing header")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

// TestRunBuildProvidersFilter checks --providers subsets the rezmoss-all feed by
// the record's provider field (including providers with no native plugin).
func TestRunBuildProvidersFilter(t *testing.T) {
	dir := t.TempDir()
	feeds := filepath.Join(dir, "feeds")
	if err := os.MkdirAll(filepath.Join(feeds, "all_providers"), 0o755); err != nil {
		t.Fatal(err)
	}
	all := `[
	  {"cidr":"52.94.0.0/22","ip_version":"IPv4","provider":"aws","service":"EC2","region":"us-east-1","last_updated":""},
	  {"cidr":"173.245.48.0/20","ip_version":"IPv4","provider":"cloudflare","service":"","region":"","last_updated":""}
	]`
	if err := os.WriteFile(filepath.Join(feeds, "all_providers", "all_providers.json"), []byte(all), 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "cloud.mmdb")
	if err := runBuild([]string{"--source", "rezmoss-all", "--fixtures", feeds, "--providers", "cloudflare", "--out", out}); err != nil {
		t.Fatalf("runBuild: %v", err)
	}
	db, err := attribution.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, found, _ := db.LookupString("52.94.0.1"); found {
		t.Error("aws should have been filtered out")
	}
	if _, found, _ := db.LookupString("173.245.48.1"); !found {
		t.Error("cloudflare should be present")
	}
}
