// Package bench runs a head-to-head between this project's MMDB reader and
// rezmoss/go-cloudip (cidranger-based) on the same real cloud IPs.
//
// To make the comparison apples-to-apples, both sides resolve the SAME IPs
// against REAL data: go-cloudip uses its embedded dataset (WithOffline), and our
// reader uses a database built once from the live rezmoss-all feed and cached at
// $TMPDIR/cloudip-bench.mmdb (first run fetches; later runs are offline).
//
//	cd bench && go test -bench . -benchmem
package bench

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ChrisLundquist/cloudip/attribution"
	gocloudip "github.com/rezmoss/go-cloudip"
)

// sampleIPs mixes real cloud addresses (hits in both datasets) with public
// non-cloud addresses (misses), so the benchmark exercises both paths.
var sampleIPs = func() []netip.Addr {
	strs := []string{
		"52.94.76.1", "52.95.245.1", "3.5.140.1", // AWS
		"34.64.0.1", "35.190.0.1", "8.34.208.1", // GCP
		"20.42.0.1", "13.66.176.1", // Azure
		"104.16.0.1", "172.64.0.1", // Cloudflare
		"129.213.0.1",                                                  // Oracle
		"8.8.8.8", "1.1.1.1", "9.9.9.9", "203.0.113.7", "198.51.100.9", // misses / non-cloud
	}
	out := make([]netip.Addr, len(strs))
	for i, s := range strs {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}()

func pick(i int) netip.Addr { return sampleIPs[i%len(sampleIPs)] }

var (
	ourOnce sync.Once
	ourDB   *attribution.DB
	ourErr  error
)

// ours builds (or loads from cache) our reader over real rezmoss-all data.
func ours(tb testing.TB) *attribution.DB {
	ourOnce.Do(func() {
		path := filepath.Join(os.TempDir(), "cloudip-bench.mmdb")
		if _, err := os.Stat(path); err != nil {
			tb.Logf("building bench DB from rezmoss-all (one-time)...")
			src := attribution.NewRezmossSource()
			entries := attribution.CollectRezmossAll(context.Background(), src, nil)
			if _, err := attribution.BuildFile(entries, path, attribution.BuildOptions{}, nil, 0, 0); err != nil {
				ourErr = err
				return
			}
		}
		ourDB, ourErr = attribution.OpenValidated(path)
	})
	if ourErr != nil {
		tb.Skipf("bench DB unavailable (needs network on first run): %v", ourErr)
	}
	return ourDB
}

func goCloudip(tb testing.TB) *gocloudip.Detector {
	d, err := gocloudip.NewDetector(gocloudip.WithOffline())
	if err != nil {
		tb.Fatalf("NewDetector: %v", err)
	}
	tb.Cleanup(func() { d.Close() })
	return d
}

// --- membership ("is this a cloud IP") -------------------------------------

func BenchmarkOurs_Contains(b *testing.B) {
	db := ours(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.Contains(pick(i))
	}
}

func BenchmarkGoCloudip_IsCloud(b *testing.B) {
	d := goCloudip(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.IsCloudProviderAddr(pick(i))
	}
}

// --- provider/region lookup -------------------------------------------------

func BenchmarkOurs_LookupProvider(b *testing.B) {
	db := ours(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = db.LookupProvider(pick(i))
	}
}

func BenchmarkOurs_LookupProviderIndexed(b *testing.B) {
	db := ours(b)
	if err := db.BuildIndex(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = db.LookupProvider(pick(i))
	}
}

func BenchmarkOurs_LookupFull(b *testing.B) {
	db := ours(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = db.Lookup(pick(i))
	}
}

func BenchmarkGoCloudip_LookupAddr(b *testing.B) {
	d := goCloudip(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.LookupAddr(pick(i))
	}
}

// TestDatasetSizes records how many networks each side carries, so the lookup
// numbers can be read in context.
func TestDatasetSizes(t *testing.T) {
	d := goCloudip(t)
	t.Logf("go-cloudip ranges: %d, providers: %v", d.RangeCount(), d.Providers())
	if db := ours(t); db != nil {
		if rep, err := attribution.Verify(db); err == nil {
			t.Logf("ours networks: %d across %d providers", rep.Networks, len(rep.ByProvider))
		}
	}
}
