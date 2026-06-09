package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ChrisLundquist/cloudip/attribution"
	_ "github.com/ChrisLundquist/cloudip/plugins/asn/all"        // register ASN plugins for the build test
	_ "github.com/ChrisLundquist/cloudip/plugins/reputation/all" // register reputation plugins for the build test
)

// asnFixture is a small ip2asn-combined.tsv: two adjacent Amazon ASNs splitting
// 52.94.8.0/22, plus an unrouted row that must be skipped.
const asnFixture = "52.94.8.0\t52.94.9.255\t8987\tIE\tAWS-GOVCLOUD\n" +
	"52.94.10.0\t52.94.21.255\t16509\tUS\tAMAZON-02\n" +
	"198.51.100.0\t198.51.100.255\t0\tNone\tNot routed\n"

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

// TestRunBuildReputationSourceValidation checks that a reputation build rejects
// the cloud-only rezmoss sources instead of silently ignoring --source, and that
// --source mirror without a configured base fails with a clear error.
func TestRunBuildReputationSourceValidation(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "reputation.mmdb")

	for _, src := range []string{"rezmoss", "rezmoss-all"} {
		err := runBuild([]string{"--reputation", "--source", src, "--providers", "tor", "--out", out})
		if err == nil || !strings.Contains(err.Error(), "cloud-only") {
			t.Errorf("--source %s should be rejected as cloud-only, got: %v", src, err)
		}
	}

	// mirror with no CLOUDIP_REPUTATION_BASE set must fail loudly, not fall back.
	t.Setenv(attribution.ReputationBaseEnv, "")
	err := runBuild([]string{"--reputation", "--source", "mirror", "--providers", "tor", "--out", out})
	if err == nil || !strings.Contains(err.Error(), attribution.ReputationBaseEnv) {
		t.Errorf("--source mirror with no base should error naming %s, got: %v", attribution.ReputationBaseEnv, err)
	}
}

// TestRunBuildReputationMirror repoints reputation feeds at an internal HTTP
// mirror (CLOUDIP_REPUTATION_BASE + --source mirror), serving the plugins'
// relative Refs(), and checks the build fetches and attributes from there.
func TestRunBuildReputationMirror(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tor/exit-list.txt" {
			_, _ = w.Write([]byte("171.25.193.25\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	t.Setenv(attribution.ReputationBaseEnv, srv.URL)
	out := filepath.Join(t.TempDir(), "reputation.mmdb")
	if err := runBuild([]string{"--reputation", "--source", "mirror", "--providers", "tor", "--out", out}); err != nil {
		t.Fatalf("mirror build: %v", err)
	}

	db, err := attribution.OpenValidated(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec, found, err := db.LookupString("171.25.193.25")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if rec.Provider != "tor" || !contains(rec.Categories, "tor_exit") {
		t.Errorf("record = %+v, want tor/tor_exit", rec)
	}
}

// TestRunBuildWithReputation drives the combined build: cloud + reputation
// feeds in one database, cloud stream first. A reputation /32 nested inside a
// cloud range must keep the cloud identity and gain the reputation categories;
// reputation-only IPs still resolve; pure cloud IPs stay category-free.
func TestRunBuildWithReputation(t *testing.T) {
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
	// One AWS range; one Tor exit INSIDE it (52.94.0.55) and one outside.
	mustWrite("aws/ip-ranges.json", `{
	  "syncToken": "1", "createDate": "2026-06-08-00-00-00",
	  "prefixes": [{"ip_prefix": "52.94.0.0/22", "region": "us-east-1", "service": "EC2", "network_border_group": "us-east-1"}],
	  "ipv6_prefixes": []
	}`)
	mustWrite("tor/exit-list.txt", "52.94.0.55\n198.51.100.7\n")
	mustWrite("feodo/ipblocklist.json", `[{"ip_address":"162.243.103.246","port":8080,"status":"offline","first_seen":"2022-06-04 21:24:53","malware":"Emotet"}]`)
	mustWrite("spamhaus/drop.txt", "; header\n1.10.16.0/20 ; SBL256894\n")

	out := filepath.Join(dir, "cloud.mmdb")
	if err := runBuild([]string{"--with-reputation", "--fixtures", feeds, "--providers", "aws", "--out", out}); err != nil {
		t.Fatalf("runBuild --with-reputation: %v", err)
	}
	db, err := attribution.OpenValidated(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// The fused record: cloud identity + reputation category on the nested /32.
	rec, found, err := db.LookupString("52.94.0.55")
	if err != nil || !found {
		t.Fatalf("nested ip: found=%v err=%v", found, err)
	}
	if rec.Provider != "aws" || rec.Region != "us-east-1" || !contains(rec.Services, "EC2") {
		t.Errorf("nested ip lost cloud identity: %+v", rec)
	}
	if !contains(rec.Categories, "tor_exit") {
		t.Errorf("nested ip categories = %v, want to contain tor_exit", rec.Categories)
	}

	// A cloud IP outside the /32 stays a clean cloud record.
	rec, _, _ = db.LookupString("52.94.0.99")
	if rec.Provider != "aws" || len(rec.Categories) != 0 {
		t.Errorf("plain cloud ip changed: %+v", rec)
	}

	// Reputation-only entries are still present (no cloud overlap needed).
	for ip, want := range map[string]string{
		"198.51.100.7":    "tor_exit",
		"162.243.103.246": "botnet_c2",
		"1.10.16.1":       "drop",
	} {
		rec, found, err := db.LookupString(ip)
		if err != nil || !found {
			t.Errorf("%s: found=%v err=%v", ip, found, err)
			continue
		}
		if !contains(rec.Categories, want) {
			t.Errorf("%s categories = %v, want to contain %q", ip, rec.Categories, want)
		}
	}
}

// TestRunBuildWithReputationFlagValidation checks the flag interactions: the two
// reputation modes are mutually exclusive, and --reputation-source is rejected
// (not silently ignored) outside a --with-reputation build.
func TestRunBuildWithReputationFlagValidation(t *testing.T) {
	out := filepath.Join(t.TempDir(), "x.mmdb")

	err := runBuild([]string{"--reputation", "--with-reputation", "--out", out})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("--reputation --with-reputation should be rejected, got: %v", err)
	}

	err = runBuild([]string{"--reputation-source", "mirror", "--out", out})
	if err == nil || !strings.Contains(err.Error(), "--with-reputation") {
		t.Errorf("--reputation-source without --with-reputation should be rejected, got: %v", err)
	}
}

// TestRunBuildASN drives the standalone IP->ASN build from a fixture and checks
// the resulting DB: provider iptoasn, asn/as_org in ext, unrouted space absent.
func TestRunBuildASN(t *testing.T) {
	dir := t.TempDir()
	feeds := filepath.Join(dir, "feeds")
	if err := os.MkdirAll(filepath.Join(feeds, "iptoasn"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(feeds, "iptoasn", "ip2asn-combined.tsv"), []byte(asnFixture), 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "asn.mmdb")
	if err := runBuild([]string{"--asn", "--fixtures", feeds, "--out", out}); err != nil {
		t.Fatalf("runBuild --asn: %v", err)
	}
	db, err := attribution.OpenValidated(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rec, found, err := db.LookupString("52.94.8.1")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if rec.Provider != "iptoasn" || rec.Ext[attribution.ExtASN] != "8987" || rec.Ext[attribution.ExtASOrg] != "AWS-GOVCLOUD" {
		t.Errorf("record = %+v, want iptoasn AS8987", rec)
	}
	if _, found, _ := db.LookupString("198.51.100.5"); found {
		t.Error("unrouted AS0 space should not be attributed")
	}
}

// TestRunBuildWithASN drives the enrichment join: an AWS /22 spanning two BGP
// announcements comes out split, each piece carrying its origin AS in ext while
// keeping the cloud identity.
func TestRunBuildWithASN(t *testing.T) {
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
	// 52.94.8.0/22 = 52.94.8.0-52.94.11.255: half announced by AS8987, half AS16509.
	mustWrite("aws/ip-ranges.json", `{
	  "syncToken": "1", "createDate": "2026-06-08-00-00-00",
	  "prefixes": [{"ip_prefix": "52.94.8.0/22", "region": "us-east-1", "service": "EC2", "network_border_group": "us-east-1"}],
	  "ipv6_prefixes": []
	}`)
	mustWrite("iptoasn/ip2asn-combined.tsv", asnFixture)

	out := filepath.Join(dir, "cloud.mmdb")
	if err := runBuild([]string{"--with-asn", "--fixtures", feeds, "--providers", "aws", "--out", out}); err != nil {
		t.Fatalf("runBuild --with-asn: %v", err)
	}
	db, err := attribution.OpenValidated(out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for ip, want := range map[string]struct{ asn, network string }{
		"52.94.8.1":  {"8987", "52.94.8.0/23"},
		"52.94.10.1": {"16509", "52.94.10.0/23"},
	} {
		rec, found, err := db.LookupString(ip)
		if err != nil || !found {
			t.Errorf("%s: found=%v err=%v", ip, found, err)
			continue
		}
		if rec.Provider != "aws" || rec.Region != "us-east-1" || !contains(rec.Services, "EC2") {
			t.Errorf("%s lost cloud identity: %+v", ip, rec)
		}
		if rec.Ext[attribution.ExtASN] != want.asn {
			t.Errorf("%s asn = %q, want %q", ip, rec.Ext[attribution.ExtASN], want.asn)
		}
		if rec.Network.String() != want.network {
			t.Errorf("%s network = %s, want %s (split at the announcement boundary)", ip, rec.Network, want.network)
		}
		// The pre-existing ext key survives alongside the stamped ones.
		if rec.Ext["network_border_group"] != "us-east-1" {
			t.Errorf("%s ext = %v, want network_border_group preserved", ip, rec.Ext)
		}
	}
}

// TestRunBuildASNFlagValidation checks the --asn/--with-asn flag interactions.
func TestRunBuildASNFlagValidation(t *testing.T) {
	out := filepath.Join(t.TempDir(), "x.mmdb")

	for _, args := range [][]string{
		{"--asn", "--reputation", "--out", out},
		{"--asn", "--with-reputation", "--out", out},
		{"--asn", "--with-asn", "--out", out},
	} {
		if err := runBuild(args); err == nil || !strings.Contains(err.Error(), "--asn") {
			t.Errorf("%v should be rejected, got: %v", args, err)
		}
	}
	if err := runBuild([]string{"--asn", "--source", "rezmoss", "--out", out}); err == nil || !strings.Contains(err.Error(), "--asn-source") {
		t.Errorf("--asn --source should be rejected, got: %v", err)
	}
	if err := runBuild([]string{"--asn-source", "mirror", "--out", out}); err == nil || !strings.Contains(err.Error(), "--with-asn") {
		t.Errorf("--asn-source alone should be rejected, got: %v", err)
	}
	// mirror with no CLOUDIP_ASN_BASE must fail loudly naming the env var.
	t.Setenv(attribution.ASNBaseEnv, "")
	if err := runBuild([]string{"--asn", "--asn-source", "mirror", "--out", out}); err == nil || !strings.Contains(err.Error(), attribution.ASNBaseEnv) {
		t.Errorf("--asn-source mirror with no base should error naming %s, got: %v", attribution.ASNBaseEnv, err)
	}
}

// TestRunBuildKeepGoing checks per-feed isolation: with one provider's fixture
// missing, --keep-going builds the rest, and without it the build fails.
func TestRunBuildKeepGoing(t *testing.T) {
	dir := t.TempDir()
	feeds := filepath.Join(dir, "feeds")
	// Provide AWS's fixture but NOT azure/gcp, so those feeds fail to open.
	if err := os.MkdirAll(filepath.Join(feeds, "aws"), 0o755); err != nil {
		t.Fatal(err)
	}
	awsFixture, err := os.ReadFile("../../plugins/aws/testdata/ip-ranges.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(feeds, "aws", "ip-ranges.json"), awsFixture, 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "cloud.mmdb")

	// keep-going (default): builds AWS, skips azure/gcp.
	if err := runBuild([]string{"--fixtures", feeds, "--out", out, "--max-skip", "0"}); err != nil {
		t.Fatalf("keep-going build should succeed: %v", err)
	}
	db, err := attribution.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	rep, _ := attribution.Verify(db)
	db.Close()
	if rep.ByProvider["aws"] == 0 {
		t.Error("expected aws networks in the partial build")
	}
	if rep.ByProvider["azure"] != 0 || rep.ByProvider["gcp"] != 0 {
		t.Error("azure/gcp should be absent (their feeds were missing)")
	}

	// --keep-going=false: a missing feed aborts the whole build.
	out2 := filepath.Join(dir, "strict.mmdb")
	if err := runBuild([]string{"--fixtures", feeds, "--out", out2, "--keep-going=false"}); err == nil {
		t.Error("strict build should fail when a feed is missing")
	}
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
