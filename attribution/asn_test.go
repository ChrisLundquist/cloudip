package attribution

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func asnTable(t *testing.T) *ASNTable {
	t.Helper()
	return NewASNTable([]ASNRange{
		{First: netip.MustParseAddr("52.94.8.0"), Last: netip.MustParseAddr("52.94.9.255"), ASN: 8987, Org: "AWS-GOVCLOUD"},
		{First: netip.MustParseAddr("52.94.10.0"), Last: netip.MustParseAddr("52.94.21.255"), ASN: 16509, Org: "AMAZON-02"},
		{First: netip.MustParseAddr("10.0.0.128"), Last: netip.MustParseAddr("10.0.0.255"), ASN: 64500, Org: "TEST"},
		{First: netip.MustParseAddr("2600:1f18::"), Last: netip.MustParseAddr("2600:1f18:ffff:ffff:ffff:ffff:ffff:ffff"), ASN: 14618, Org: "AMAZON-AES"},
	})
}

// collect drains an entry stream, failing the test on any stream error.
func collectEntries(t *testing.T, s func(func(Entry, error) bool)) []Entry {
	t.Helper()
	var out []Entry
	for e, err := range s {
		if err != nil {
			t.Fatalf("stream error: %v", err)
		}
		out = append(out, e)
	}
	return out
}

// TestEnrichASNSplitsAtBoundaries is the core guarantee: a cloud CIDR spanning
// two BGP announcements is split at the boundary, each piece stamped with its
// own origin AS — the AWS reality where a published /21 is announced partly by
// AS8987 (GovCloud) and partly by AS16509.
func TestEnrichASNSplitsAtBoundaries(t *testing.T) {
	in := []Entry{{
		Network: mustPrefix(t, "52.94.8.0/21"), // 52.94.8.0 - 52.94.15.255
		Record:  Record{Provider: "aws", Region: "us-east-1", Services: []string{"EC2"}, Ext: map[string]string{"k": "v"}},
	}}
	got := collectEntries(t, EnrichASN(entriesFrom(in), asnTable(t)))

	want := map[string]string{ // network -> asn
		"52.94.8.0/23":  "8987",
		"52.94.10.0/23": "16509",
		"52.94.12.0/22": "16509",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for _, e := range got {
		asn, ok := want[e.Network.String()]
		if !ok {
			t.Errorf("unexpected piece %s", e.Network)
			continue
		}
		if e.Record.Ext[ExtASN] != asn {
			t.Errorf("%s asn = %q, want %q", e.Network, e.Record.Ext[ExtASN], asn)
		}
		// The cloud identity and pre-existing ext survive the stamping.
		if e.Record.Provider != "aws" || e.Record.Region != "us-east-1" || e.Record.Ext["k"] != "v" {
			t.Errorf("%s lost record fields: %+v", e.Network, e.Record)
		}
	}
	// The input record's ext map must not have been mutated in place.
	if _, leaked := in[0].Record.Ext[ExtASN]; leaked {
		t.Error("EnrichASN mutated the input ext map")
	}
}

// TestEnrichASNGaps checks unannounced space inside an entry: it is emitted
// unstamped rather than dropped or mis-attributed.
func TestEnrichASNGaps(t *testing.T) {
	in := []Entry{{Network: mustPrefix(t, "10.0.0.0/24"), Record: Record{Provider: "gcp"}}}
	got := collectEntries(t, EnrichASN(entriesFrom(in), asnTable(t)))
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].Network.String() != "10.0.0.0/25" || got[0].Record.Ext[ExtASN] != "" {
		t.Errorf("gap piece = %s ext=%v, want 10.0.0.0/25 unstamped", got[0].Network, got[0].Record.Ext)
	}
	if got[1].Network.String() != "10.0.0.128/25" || got[1].Record.Ext[ExtASN] != "64500" {
		t.Errorf("covered piece = %s ext=%v, want 10.0.0.128/25 asn 64500", got[1].Network, got[1].Record.Ext)
	}
}

// TestEnrichASNPassThrough checks entries nothing announces (and v4/v6 family
// separation: a v4 entry must never match a v6 row).
func TestEnrichASNPassThrough(t *testing.T) {
	in := []Entry{
		{Network: mustPrefix(t, "192.0.2.0/24"), Record: Record{Provider: "gcp"}},
		{Network: mustPrefix(t, "2600:1f18::/40"), Record: Record{Provider: "aws"}},
	}
	got := collectEntries(t, EnrichASN(entriesFrom(in), asnTable(t)))
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].Network.String() != "192.0.2.0/24" || len(got[0].Record.Ext) != 0 {
		t.Errorf("unannounced v4 entry changed: %+v", got[0])
	}
	if got[1].Record.Ext[ExtASN] != "14618" {
		t.Errorf("v6 entry ext = %v, want asn 14618", got[1].Record.Ext)
	}
}

// TestEnrichASNBuildEndToEnd runs enriched entries through Build and checks the
// stamped ext survives storage and lookup (the nginx-visible path) — and that
// the service-union merge still works after splitting: AWS lists the same CIDR
// once per owning service, so the split pieces of both listings must land on
// the same tree nodes and union their services.
func TestEnrichASNBuildEndToEnd(t *testing.T) {
	in := []Entry{
		{Network: mustPrefix(t, "52.94.8.0/21"), Record: Record{Provider: "aws", Services: []string{"EC2"}}},
		{Network: mustPrefix(t, "52.94.8.0/21"), Record: Record{Provider: "aws", Services: []string{"S3"}}},
	}
	var buf bytes.Buffer
	if _, err := Build(EnrichASN(entriesFrom(in), asnTable(t)), &buf, BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	db, err := OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	rec, found, _ := db.LookupString("52.94.8.1")
	if !found || rec.Ext[ExtASN] != "8987" || rec.Ext[ExtASOrg] != "AWS-GOVCLOUD" {
		t.Errorf("52.94.8.1 = found=%v ext=%v, want asn 8987 AWS-GOVCLOUD", found, rec.Ext)
	}
	rec, _, _ = db.LookupString("52.94.10.1")
	if rec.Ext[ExtASN] != "16509" || rec.Provider != "aws" {
		t.Errorf("52.94.10.1 = %+v, want aws via asn 16509", rec)
	}
	if strings.Join(rec.Services, ",") != "EC2,S3" {
		t.Errorf("services = %v, want EC2,S3 union to survive splitting", rec.Services)
	}
}

// TestCoalesceASNRanges pins the table normalization the binary search relies
// on: overlapping rows clamp to first-match (a fully-contained row drops), and
// adjacent same-AS rows merge (iptoasn splits ranges on country changes, a
// field we discard).
func TestCoalesceASNRanges(t *testing.T) {
	a := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	got := CoalesceASNRanges([]ASNRange{
		// Overlap: a wide first-writer row, then a nested row that must drop and
		// a tail row that must clamp.
		{First: a("10.0.0.0"), Last: a("10.0.200.255"), ASN: 100, Org: "WIDE"},
		{First: a("10.0.1.0"), Last: a("10.0.1.255"), ASN: 200, Org: "NESTED"},
		{First: a("10.0.100.0"), Last: a("10.0.255.255"), ASN: 300, Org: "TAIL"},
		// Adjacent same-AS rows (a country split in the feed): must merge.
		{First: a("20.0.0.0"), Last: a("20.0.0.255"), ASN: 5, Org: "SAME"},
		{First: a("20.0.1.0"), Last: a("20.0.1.255"), ASN: 5, Org: "SAME"},
	})
	want := []ASNRange{
		{First: a("10.0.0.0"), Last: a("10.0.200.255"), ASN: 100, Org: "WIDE"},
		{First: a("10.0.201.0"), Last: a("10.0.255.255"), ASN: 300, Org: "TAIL"},
		{First: a("20.0.0.0"), Last: a("20.0.1.255"), ASN: 5, Org: "SAME"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Regression for the pre-coalesce miss: a /24 covered only by the wide row
	// used to pass through unstamped because overlap broke the binary search's
	// monotonicity assumption. It must now be stamped.
	in := []Entry{{Network: mustPrefix(t, "10.0.50.0/24"), Record: Record{Provider: "gcp"}}}
	table := NewASNTable([]ASNRange{
		{First: a("10.0.0.0"), Last: a("10.0.200.255"), ASN: 100, Org: "WIDE"},
		{First: a("10.0.1.0"), Last: a("10.0.1.255"), ASN: 200, Org: "NESTED"},
	})
	out := collectEntries(t, EnrichASN(entriesFrom(in), table))
	if len(out) != 1 || out[0].Record.Ext[ExtASN] != "100" {
		t.Errorf("enrich under overlap = %+v, want one piece stamped asn 100", out)
	}
}
