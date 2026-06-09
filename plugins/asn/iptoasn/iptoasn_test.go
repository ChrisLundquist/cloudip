package iptoasn

import (
	"bytes"
	"compress/gzip"
	"os"
	"testing"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func parseFixture(t *testing.T) []attribution.ASNRange {
	t.Helper()
	f, err := os.Open("testdata/ip2asn-combined.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := ParseTable(f)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestParseTable(t *testing.T) {
	rows := parseFixture(t)
	// 5 fixture lines, one of them unrouted (AS0) and skipped.
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want 4: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.First.String() != "1.178.4.0" || r.Last.String() != "1.178.6.255" || r.ASN != 14618 || r.Org != "AMAZON-AES" {
		t.Errorf("row 0 = %+v", r)
	}
	if rows[3].First.Is4() {
		t.Errorf("row 3 should be the v6 range, got %+v", rows[3])
	}
}

// TestParseTableGzip checks the magic-byte sniffing: the live feed is .tsv.gz.
func TestParseTableGzip(t *testing.T) {
	plain, err := os.ReadFile("testdata/ip2asn-combined.tsv")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err := ParseTable(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Errorf("gzip rows = %d, want 4", len(rows))
	}
}

// TestParse checks the standalone-database entries: ranges become CIDR-aligned
// prefixes carrying asn/as_org in ext, unrouted space is absent.
func TestParse(t *testing.T) {
	f, err := os.Open("testdata/ip2asn-combined.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	byNetwork := map[string]attribution.Record{}
	for e, err := range (Plugin{}).Parse("iptoasn/ip2asn-combined.tsv", f) {
		if err != nil {
			t.Fatal(err)
		}
		byNetwork[e.Network.String()] = e.Record
	}

	// 1.178.4.0-1.178.6.255 is not CIDR-aligned: /23 + /24.
	for _, n := range []string{"1.178.4.0/23", "1.178.6.0/24"} {
		rec, ok := byNetwork[n]
		if !ok {
			t.Errorf("missing %s (networks: %v)", n, len(byNetwork))
			continue
		}
		if rec.Provider != "iptoasn" || rec.Ext[attribution.ExtASN] != "14618" || rec.Ext[attribution.ExtASOrg] != "AMAZON-AES" {
			t.Errorf("%s record = %+v", n, rec)
		}
	}
	// Unrouted (AS0) space must not be present.
	if _, ok := byNetwork["198.51.100.0/24"]; ok {
		t.Error("unrouted AS0 range leaked into entries")
	}
	// The v6 range is present and tagged.
	if rec, ok := byNetwork["2600:1f18::/32"]; !ok || rec.Ext[attribution.ExtASN] != "14618" {
		t.Errorf("v6 range = ok=%v %+v", ok, rec)
	}
}
