package attribution

import (
	"bytes"
	"iter"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// entriesFrom builds an iter.Seq2 from a fixed slice for testing Build.
func entriesFrom(es []Entry) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		for _, e := range es {
			if !yield(e, nil) {
				return
			}
		}
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad prefix %q: %v", s, err)
	}
	return p
}

// TestBuildMergesServices is the central guarantee: the same CIDR inserted once
// per service must end up with the union of services, not the last one.
func TestBuildMergesServices(t *testing.T) {
	synced := time.Unix(1718000000, 0).UTC()
	es := []Entry{
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Region: "us-east-1", Services: []string{"AMAZON"}, Source: "x", SyncedAt: synced, Ext: map[string]string{"network_border_group": "us-east-1"}}},
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Region: "us-east-1", Services: []string{"EC2"}, Source: "x", SyncedAt: synced}},
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Region: "us-east-1", Services: []string{"S3"}, Source: "x", SyncedAt: synced}},
		{Network: mustPrefix(t, "2600:1f00::/24"), Record: Record{Provider: "aws", Region: "us-east-1", Services: []string{"EC2"}, Source: "x", SyncedAt: synced}},
	}

	var buf bytes.Buffer
	stats, err := Build(entriesFrom(es), &buf, BuildOptions{BuildEpoch: 1718000000})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if stats.Inserted != 4 || stats.Skipped != 0 {
		t.Errorf("stats = %+v, want 4 inserted / 0 skipped", stats)
	}

	db, err := OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	defer db.Close()

	if db.Metadata().DatabaseType != DatabaseType {
		t.Errorf("DatabaseType = %q, want %q", db.Metadata().DatabaseType, DatabaseType)
	}

	rec, found, err := db.LookupString("52.94.0.1")
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if got := strings.Join(rec.Services, ","); got != "AMAZON,EC2,S3" {
		t.Errorf("services = %q, want AMAZON,EC2,S3 (sorted union)", got)
	}
	if rec.IPv6 {
		t.Error("v4 network marked IPv6")
	}
	if rec.Ext["network_border_group"] != "us-east-1" {
		t.Errorf("ext lost on merge: %v", rec.Ext)
	}
	if !rec.SyncedAt.Equal(synced) {
		t.Errorf("synced_at = %v, want %v", rec.SyncedAt, synced)
	}

	v6, found, err := db.LookupString("2600:1f00::1")
	if err != nil || !found {
		t.Fatalf("v6 lookup: found=%v err=%v", found, err)
	}
	if !v6.IPv6 {
		t.Error("v6 network not marked IPv6")
	}

	// Unknown IP is not found, with no error.
	_, found, err = db.LookupString("203.0.113.1")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if found {
		t.Error("203.0.113.1 should not be attributed")
	}
}

// TestBuildSkipsAliased ensures a feed that lists an aliased 6to4 range is not
// fatal: the bad network is skipped and counted, the rest is built.
func TestBuildSkipsAliased(t *testing.T) {
	es := []Entry{
		{Network: mustPrefix(t, "2002::/16"), Record: Record{Provider: "weird", Services: []string{"x"}}}, // aliased
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Services: []string{"EC2"}}},
	}
	var buf bytes.Buffer
	stats, err := Build(entriesFrom(es), &buf, BuildOptions{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if stats.Inserted != 1 || stats.Skipped != 1 {
		t.Errorf("stats = %+v, want 1 inserted / 1 skipped", stats)
	}
	db, err := OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, found, _ := db.LookupString("52.94.0.1"); !found {
		t.Error("aws network missing after aliased skip")
	}
}

// TestBuildV4MappedPrefix guards the fix for v4-in-v6 prefixes being dropped:
// a ::ffff:x range must be stored as native IPv4 and found by a v4 lookup.
func TestBuildV4MappedPrefix(t *testing.T) {
	es := []Entry{
		{Network: mustPrefix(t, "::ffff:5.6.7.0/120"), Record: Record{Provider: "aws", Region: "us-east-1", Services: []string{"EC2"}}},
	}
	var buf bytes.Buffer
	stats, err := Build(entriesFrom(es), &buf, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Inserted != 1 || stats.Skipped != 0 {
		t.Fatalf("stats = %+v, want 1 inserted / 0 skipped (v4-mapped must not be skipped)", stats)
	}
	db, err := OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec, found, err := db.LookupString("5.6.7.1")
	if err != nil || !found {
		t.Fatalf("v4 lookup of v4-mapped insert: found=%v err=%v", found, err)
	}
	if rec.IPv6 {
		t.Error("v4-mapped network wrongly marked IPv6")
	}
}

// TestBuildCrossProviderKeepsFirst guards the fix for cross-provider clobbering:
// when two providers claim the same prefix, the first writer wins intact and the
// other provider's service must NOT leak into its record.
func TestBuildCrossProviderKeepsFirst(t *testing.T) {
	es := []Entry{
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Region: "us-east-1", Services: []string{"EC2"}}},
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "gcp", Region: "us-central1", Services: []string{"compute"}}},
	}
	var buf bytes.Buffer
	if _, err := Build(entriesFrom(es), &buf, BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	db, err := OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec, _, _ := db.LookupString("52.94.0.1")
	if rec.Provider != "aws" || rec.Region != "us-east-1" {
		t.Errorf("cross-provider merge changed identity: %+v", rec)
	}
	if strings.Join(rec.Services, ",") != "EC2" {
		t.Errorf("foreign provider service leaked into record: %v", rec.Services)
	}
}

// TestMergeKeepsFreshestSyncedAt guards that a same-provider merge keeps the
// newest feed timestamp regardless of insert order.
func TestMergeKeepsFreshestSyncedAt(t *testing.T) {
	older := time.Unix(1000, 0).UTC()
	newer := time.Unix(2000, 0).UTC()
	// Insert newer first, then older: the merged record must keep newer.
	es := []Entry{
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Services: []string{"EC2"}, SyncedAt: newer}},
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Services: []string{"S3"}, SyncedAt: older}},
	}
	var buf bytes.Buffer
	if _, err := Build(entriesFrom(es), &buf, BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	db, err := OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec, _, _ := db.LookupString("52.94.0.1")
	if !rec.SyncedAt.Equal(newer) {
		t.Errorf("synced_at = %v, want freshest %v", rec.SyncedAt, newer)
	}
	if strings.Join(rec.Services, ",") != "EC2,S3" {
		t.Errorf("services = %v, want union EC2,S3", rec.Services)
	}
}

// TestBuildRejectsPoisoningV4in6 guards the HIGH bug: a 4-in-6 prefix shorter
// than /96 must be skipped, never inserted as 0.0.0.0/0 (which would attribute
// all of IPv4 to one provider).
func TestBuildRejectsPoisoningV4in6(t *testing.T) {
	es := []Entry{
		{Network: mustPrefix(t, "::ffff:0:0/95"), Record: Record{Provider: "evil", Services: []string{"X"}}},
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Services: []string{"EC2"}}},
	}
	var buf bytes.Buffer
	stats, err := Build(entriesFrom(es), &buf, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Inserted != 1 || stats.Skipped != 1 {
		t.Fatalf("stats = %+v, want 1 inserted / 1 skipped", stats)
	}
	db, err := OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Arbitrary public v4 must NOT be attributed (no default-route poisoning).
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "203.0.113.7"} {
		if rec, found, _ := db.LookupString(ip); found {
			t.Errorf("%s wrongly attributed to %q (default route poisoned)", ip, rec.Provider)
		}
	}
	if _, found, _ := db.LookupString("52.94.0.1"); !found {
		t.Error("legit aws network missing")
	}
}

// TestExportCSVIPv6Bounds covers the 128-bit big.Int branch of rangeBounds by
// checking the emitted bounds satisfy the invariant end-start+1 == 2^hostbits and
// start == integer(network address), computed independently here.
func TestExportCSVIPv6Bounds(t *testing.T) {
	es := []Entry{
		{Network: mustPrefix(t, "2600:1f00::/24"), Record: Record{Provider: "aws", Services: []string{"EC2"}}},
	}
	var mmdb bytes.Buffer
	if _, err := Build(entriesFrom(es), &mmdb, BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	db, err := OpenBytes(mmdb.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var csv bytes.Buffer
	if _, err := ExportCSV(db, &csv); err != nil {
		t.Fatal(err)
	}

	// Find the data row and pull start/end columns.
	var row string
	for _, line := range strings.Split(csv.String(), "\n") {
		if strings.HasPrefix(line, "2600:1f00::/24,") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatalf("no v6 row in CSV:\n%s", csv.String())
	}
	cols := strings.Split(row, ",")
	start, ok := new(big.Int).SetString(cols[1], 10)
	if !ok {
		t.Fatalf("bad start int %q", cols[1])
	}
	end, ok := new(big.Int).SetString(cols[2], 10)
	if !ok {
		t.Fatalf("bad end int %q", cols[2])
	}

	// Expected start = integer of 2600:1f00:: (the masked network address).
	a := netip.MustParseAddr("2600:1f00::").As16()
	wantStart := new(big.Int).SetBytes(a[:])
	if start.Cmp(wantStart) != 0 {
		t.Errorf("v6 start = %s, want %s", start, wantStart)
	}
	// end - start + 1 must equal 2^(128-24).
	span := new(big.Int).Add(new(big.Int).Sub(end, start), big.NewInt(1))
	wantSpan := new(big.Int).Lsh(big.NewInt(1), 128-24)
	if span.Cmp(wantSpan) != 0 {
		t.Errorf("v6 span = %s, want 2^104 = %s", span, wantSpan)
	}
}

// TestCategoriesUnionAcrossProviders is the reputation overlay guarantee: when a
// cloud record and a reputation record (or two reputation feeds) cover the same
// prefix, categories union even though provider/services keep the first writer.
func TestCategoriesUnionAcrossProviders(t *testing.T) {
	es := []Entry{
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Region: "us-east-1", Services: []string{"EC2"}}},
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "tor", Categories: []string{"tor_exit"}}},
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "abuse.ch", Categories: []string{"botnet_c2"}}},
	}
	var buf bytes.Buffer
	if _, err := Build(entriesFrom(es), &buf, BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	db, err := OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec, found, _ := db.LookupString("52.94.0.1")
	if !found {
		t.Fatal("not found")
	}
	// First writer keeps provider/region/services...
	if rec.Provider != "aws" || rec.Region != "us-east-1" {
		t.Errorf("identity changed: %+v", rec)
	}
	if strings.Join(rec.Services, ",") != "EC2" {
		t.Errorf("services = %v, want only EC2", rec.Services)
	}
	// ...but categories accumulate across all providers.
	if got := strings.Join(rec.Categories, ","); got != "botnet_c2,tor_exit" {
		t.Errorf("categories = %q, want botnet_c2,tor_exit (sorted union)", got)
	}
}

// TestPureCloudHasNoCategories confirms cloud-only records carry no categories
// key (the cloud storage path stays byte-clean).
func TestPureCloudHasNoCategories(t *testing.T) {
	es := []Entry{
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Services: []string{"EC2"}}},
	}
	var buf bytes.Buffer
	if _, err := Build(entriesFrom(es), &buf, BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	db, err := OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec, _, _ := db.LookupString("52.94.0.1")
	if len(rec.Categories) != 0 {
		t.Errorf("cloud record gained categories: %v", rec.Categories)
	}
}

func TestBuildVersionAndVerify(t *testing.T) {
	es := []Entry{
		{Network: mustPrefix(t, "13.248.0.0/16"), Record: Record{Provider: "aws", Services: []string{"EC2"}}},
		{Network: mustPrefix(t, "2600:1900::/28"), Record: Record{Provider: "gcp", Region: "us-central1", Services: []string{"Google Cloud"}}},
	}
	var buf bytes.Buffer
	if _, err := Build(entriesFrom(es), &buf, BuildOptions{BuildEpoch: 1718000000}); err != nil {
		t.Fatal(err)
	}
	db, err := OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if got := db.BuildTime().Unix(); got != 1718000000 {
		t.Errorf("BuildTime = %d, want 1718000000", got)
	}

	rep, err := Verify(db)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Networks != 2 || rep.IPv4 != 1 || rep.IPv6 != 1 {
		t.Errorf("report = %+v", rep)
	}
	if rep.ByProvider["aws"] != 1 || rep.ByProvider["gcp"] != 1 {
		t.Errorf("byProvider = %v", rep.ByProvider)
	}
}

func TestExportCSV(t *testing.T) {
	es := []Entry{
		{Network: mustPrefix(t, "52.94.0.0/22"), Record: Record{Provider: "aws", Region: "us-east-1", Services: []string{"EC2", "S3"}, SyncedAt: time.Unix(1718000000, 0)}},
	}
	var mmdb bytes.Buffer
	if _, err := Build(entriesFrom(es), &mmdb, BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	db, err := OpenBytes(mmdb.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var csv bytes.Buffer
	n, err := ExportCSV(db, &csv)
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	if n != 1 {
		t.Errorf("exported %d rows, want 1", n)
	}
	out := csv.String()
	if !strings.Contains(out, "network_cidr,start_ip_int,end_ip_int") {
		t.Errorf("missing header: %q", out)
	}
	// 52.94.0.0 = 52*2^24 + 94*2^16 = 878575616; /22 spans 1024 addresses.
	if !strings.Contains(out, "52.94.0.0/22,878575616,878576639") {
		t.Errorf("bad range bounds in CSV:\n%s", out)
	}
	if !strings.Contains(out, `"EC2,S3"`) {
		t.Errorf("services not joined/quoted:\n%s", out)
	}
}
