package attribution

import (
	"strings"
	"testing"
	"time"
)

// drainBounded iterates a parser to completion but fails if it yields more than
// `limit` items — catching a non-terminating decoder (the infinite-loop bug).
func drainBounded(t *testing.T, seq func(func(Entry, error) bool), limit int) (n int, sawErr bool) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, err := range seq {
			n++
			if err != nil {
				sawErr = true
			}
			if n > limit {
				return // bail; the test will fail on the count
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("parser did not terminate within 5s (likely infinite loop)")
	}
	return n, sawErr
}

// TestParseRezmossMalformedTerminates guards the fix where a JSON syntax error
// mid-array must end the stream instead of re-yielding forever.
func TestParseRezmossMalformedTerminates(t *testing.T) {
	const bad = `[{"ip_address":"1.2.3.0/24","ip_type":"IPv4","service":"x","region":""}, {oops not json`
	n, sawErr := drainBounded(t, func(yield func(Entry, error) bool) {
		for e, err := range ParseRezmoss("aws")("aws/aws_ips.json", strings.NewReader(bad)) {
			if !yield(e, err) {
				return
			}
		}
	}, 100)
	if !sawErr {
		t.Error("expected a parse error")
	}
	if n > 5 {
		t.Errorf("parser yielded %d items on malformed input (should terminate quickly)", n)
	}
}

func TestParseRezmossAllMalformedTerminates(t *testing.T) {
	const bad = `[{"cidr":"1.2.3.0/24","ip_version":"IPv4","provider":"aws","service":"x","region":"","last_updated":""}, {oops`
	n, sawErr := drainBounded(t, func(yield func(Entry, error) bool) {
		for e, err := range ParseRezmossAll(nil)(RezmossAllRef, strings.NewReader(bad)) {
			if !yield(e, err) {
				return
			}
		}
	}, 100)
	if !sawErr {
		t.Error("expected a parse error")
	}
	if n > 5 {
		t.Errorf("parser yielded %d items on malformed input (should terminate quickly)", n)
	}
}

func TestParseRezmoss(t *testing.T) {
	const feed = `[
	  {"ip_address":"3.4.12.4/32","ip_type":"IPv4","service":"AMAZON","region":"eu-west-1"},
	  {"ip_address":"23.228.249.0/24","ip_type":"IPv4","service":"AMAZON","region":"GLOBAL"},
	  {"ip_address":"2600:1f00::/24","ip_type":"IPv6","service":"EC2","region":"us-east-1"}
	]`

	var entries []Entry
	for e, err := range ParseRezmoss("aws")("aws/aws_ips.json", strings.NewReader(feed)) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if entries[0].Record.Provider != "aws" || entries[0].Record.Services[0] != "AMAZON" {
		t.Errorf("entry0 = %+v", entries[0].Record)
	}
	// "GLOBAL" is normalized to an empty region.
	if entries[1].Record.Region != "" {
		t.Errorf("GLOBAL region not normalized: %q", entries[1].Record.Region)
	}
	if !entries[2].Network.Addr().Is6() {
		t.Error("expected v6 prefix")
	}
}

// TestParseRezmossBareIP guards the fix where a bare host IP (no '/') in a
// rezmoss feed is accepted as a single-host prefix instead of failing the build.
func TestParseRezmossBareIP(t *testing.T) {
	const feed = `[
	  {"ip_address":"5.134.119.103","ip_type":"IPv4","service":"AMAZON","region":"us-east-1"},
	  {"ip_address":"2600:1f00::5","ip_type":"IPv6","service":"EC2","region":"us-east-1"}
	]`

	var entries []Entry
	for e, err := range ParseRezmoss("aws")("aws/aws_ips.json", strings.NewReader(feed)) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if got := entries[0].Network.String(); got != "5.134.119.103/32" {
		t.Errorf("v4 bare IP = %q, want 5.134.119.103/32", got)
	}
	if got := entries[1].Network.String(); got != "2600:1f00::5/128" {
		t.Errorf("v6 bare IP = %q, want 2600:1f00::5/128", got)
	}
}

// TestParseRezmossAllBareIP is the same guard for the unified all_providers feed,
// whose "cidr" field triggered the CI build failure.
func TestParseRezmossAllBareIP(t *testing.T) {
	const feed = `[
	  {"cidr":"5.134.119.103","ip_version":"IPv4","provider":"aws","service":"AMAZON","region":"us-east-1","last_updated":"2026-06-08 03:23:35"},
	  {"cidr":"52.94.0.0/22","ip_version":"IPv4","provider":"aws","service":"AMAZON","region":"us-east-1","last_updated":"2026-06-08 03:23:35"}
	]`

	var entries []Entry
	for e, err := range ParseRezmossAll(nil)(RezmossAllRef, strings.NewReader(feed)) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if got := entries[0].Network.String(); got != "5.134.119.103/32" {
		t.Errorf("bare IP = %q, want 5.134.119.103/32", got)
	}
	// A genuinely malformed field still surfaces an error.
	var sawErr bool
	const bad = `[{"cidr":"not-an-ip","ip_version":"IPv4","provider":"aws","service":"x","region":"","last_updated":""}]`
	for _, err := range ParseRezmossAll(nil)(RezmossAllRef, strings.NewReader(bad)) {
		if err != nil {
			sawErr = true
		}
	}
	if !sawErr {
		t.Error("expected a parse error on a non-IP cidr field")
	}
}

func TestRezmossRefsDefaultAndOverride(t *testing.T) {
	// Default convention.
	def := testPlugin{name: "aws"}
	if got := RezmossRefs(def); len(got) != 1 || got[0] != "aws/aws_ips.json" {
		t.Errorf("default RezmossRefs = %v", got)
	}
	// Override via RezmossPlugin.
	ov := rezmossOverridePlugin{testPlugin{name: "gcp"}}
	if got := RezmossRefs(ov); len(got) != 1 || got[0] != "googlecloud/googlecloud_ips.json" {
		t.Errorf("override RezmossRefs = %v", got)
	}
}

type rezmossOverridePlugin struct{ testPlugin }

func (rezmossOverridePlugin) RezmossRefs() []string {
	return []string{"googlecloud/googlecloud_ips.json"}
}

func TestParseRezmossAll(t *testing.T) {
	const feed = `[
	  {"cidr":"173.245.48.0/20","ip_version":"IPv4","provider":"cloudflare","service":"","region":"","last_updated":"2026-06-08 03:23:35"},
	  {"cidr":"52.94.0.0/22","ip_version":"IPv4","provider":"aws","service":"AMAZON","region":"us-east-1","last_updated":"2026-06-08 03:23:35"},
	  {"cidr":"170.114.0.0/16","ip_version":"IPv4","provider":"zoom","service":"zoom","region":"GLOBAL","last_updated":"2026-06-08 03:23:35"}
	]`

	// No filter: every provider passes through, provider taken from the record.
	var all []Entry
	for e, err := range ParseRezmossAll(nil)(RezmossAllRef, strings.NewReader(feed)) {
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, e)
	}
	if len(all) != 3 {
		t.Fatalf("got %d entries, want 3", len(all))
	}
	if all[0].Record.Provider != "cloudflare" {
		t.Errorf("provider = %q, want cloudflare", all[0].Record.Provider)
	}
	if all[0].Record.SyncedAt.IsZero() {
		t.Error("last_updated not parsed into synced_at")
	}
	if all[2].Record.Region != "" { // GLOBAL normalized away
		t.Errorf("GLOBAL not normalized: %q", all[2].Record.Region)
	}

	// Filter to a subset of providers.
	var filtered []Entry
	for e, err := range ParseRezmossAll(map[string]bool{"aws": true})(RezmossAllRef, strings.NewReader(feed)) {
		if err != nil {
			t.Fatal(err)
		}
		filtered = append(filtered, e)
	}
	if len(filtered) != 1 || filtered[0].Record.Provider != "aws" {
		t.Errorf("filtered = %+v, want only aws", filtered)
	}
}
