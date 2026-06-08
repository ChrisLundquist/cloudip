package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChrisLundquist/cloudip/attribution"
	_ "github.com/ChrisLundquist/cloudip/plugins/reputation/all" // register reputation plugins for the build test
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

// TestRunBuildReputation drives runBuild --reputation against local fixtures and
// checks the resulting DB attributes IPs to reputation categories.
func TestRunBuildReputation(t *testing.T) {
	dir := t.TempDir()
	feeds := filepath.Join(dir, "feeds")
	mustWrite := func(rel, content string) {
		p := filepath.Join(feeds, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("feodo/ipblocklist.json", `[{"ip_address":"162.243.103.246","port":8080,"status":"offline","first_seen":"2022-06-04 21:24:53","malware":"Emotet"}]`)
	mustWrite("spamhaus/drop.txt", "; header\n1.10.16.0/20 ; SBL256894\n")
	mustWrite("tor/exit-list.txt", "171.25.193.25\n")

	out := filepath.Join(dir, "reputation.mmdb")
	if err := runBuild([]string{"--reputation", "--fixtures", feeds, "--out", out}); err != nil {
		t.Fatalf("runBuild --reputation: %v", err)
	}
	db, err := attribution.OpenValidated(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cases := map[string]struct{ provider, category string }{
		"162.243.103.246": {"abuse.ch", "botnet_c2"},
		"1.10.16.1":       {"spamhaus", "drop"},
		"171.25.193.25":   {"tor", "tor_exit"},
	}
	for ip, want := range cases {
		rec, found, err := db.LookupString(ip)
		if err != nil || !found {
			t.Errorf("%s: found=%v err=%v", ip, found, err)
			continue
		}
		if rec.Provider != want.provider {
			t.Errorf("%s provider = %q, want %q", ip, rec.Provider, want.provider)
		}
		if !contains(rec.Categories, want.category) {
			t.Errorf("%s categories = %v, want to contain %q", ip, rec.Categories, want.category)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestRunBuildReputationDefaultOut guards the footgun fix: a --reputation build
// with no --out writes reputation.mmdb, NOT cloud.mmdb, so it can't clobber a
// cloud database that happens to sit in the working directory.
func TestRunBuildReputationDefaultOut(t *testing.T) {
	dir := t.TempDir()
	feeds := filepath.Join(dir, "feeds")
	if err := os.MkdirAll(filepath.Join(feeds, "tor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(feeds, "tor", "exit-list.txt"), []byte("171.25.193.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Pre-seed a cloud.mmdb in the working dir that must be left untouched.
	cloudPath := filepath.Join(dir, "cloud.mmdb")
	if _, err := attribution.BuildFile(seqOne(t, "8.8.8.0/24", "aws"), cloudPath, attribution.BuildOptions{}, nil, 0, 0); err != nil {
		t.Fatal(err)
	}
	cloudBefore, _ := os.ReadFile(cloudPath)

	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)

	// No --out, no --providers: builds all reputation feeds (here just tor via fixtures).
	if err := runBuild([]string{"--reputation", "--fixtures", feeds, "--providers", "tor"}); err != nil {
		t.Fatalf("runBuild: %v", err)
	}

	if _, err := os.Stat("reputation.mmdb"); err != nil {
		t.Errorf("expected reputation.mmdb to be created: %v", err)
	}
	cloudAfter, _ := os.ReadFile(cloudPath)
	if !bytes.Equal(cloudBefore, cloudAfter) {
		t.Error("reputation build clobbered cloud.mmdb")
	}
}

func seqOne(t *testing.T, cidr, provider string) func(func(attribution.Entry, error) bool) {
	t.Helper()
	pre := mustParsePrefix(t, cidr)
	return func(yield func(attribution.Entry, error) bool) {
		yield(attribution.Entry{Network: pre, Record: attribution.Record{Provider: provider, Services: []string{"X"}}}, nil)
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
