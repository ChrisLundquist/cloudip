package attribution

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
)

// benchDB builds an in-memory MMDB with n distinct /24 networks spread across a
// few providers/regions, returning the opened DB and a deterministic set of IPs
// that hit it. It models a realistic cloud-attribution database.
func benchDB(b *testing.B, n int) (*DB, []netip.Addr) {
	b.Helper()
	providers := []string{"aws", "azure", "gcp", "cloudflare", "oracle"}
	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-south-1"}

	entries := func(yield func(Entry, error) bool) {
		for i := 0; i < n; i++ {
			// Spread across 1.0.0.0/8 .. 1.x.y.0/24 to avoid aggregation.
			a := byte(1 + (i>>16)&0x3f)
			bb := byte((i >> 8) & 0xff)
			c := byte(i & 0xff)
			p := netip.PrefixFrom(netip.AddrFrom4([4]byte{a, bb, c, 0}), 24)
			rec := Record{
				Provider: providers[i%len(providers)],
				Region:   regions[i%len(regions)],
				Services: []string{"S1", "S2"},
				Ext:      map[string]string{"k": "v"},
			}
			if !yield(Entry{Network: p, Record: rec}, nil) {
				return
			}
		}
	}
	var buf bytes.Buffer
	if _, err := Build(entries, &buf, BuildOptions{}); err != nil {
		b.Fatal(err)
	}
	db, err := OpenBytes(buf.Bytes())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { db.Close() })

	// Deterministic hit IPs (host .42 within each /24).
	rng := rand.New(rand.NewSource(1))
	ips := make([]netip.Addr, 4096)
	for i := range ips {
		j := rng.Intn(n)
		a := byte(1 + (j>>16)&0x3f)
		bb := byte((j >> 8) & 0xff)
		c := byte(j & 0xff)
		ips[i] = netip.AddrFrom4([4]byte{a, bb, c, 42})
	}
	return db, ips
}

const benchN = 200_000

func BenchmarkLookupFull(b *testing.B) {
	db, ips := benchDB(b, benchN)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = db.Lookup(ips[i&(len(ips)-1)])
	}
}

func BenchmarkLookupProvider(b *testing.B) {
	db, ips := benchDB(b, benchN)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = db.LookupProvider(ips[i&(len(ips)-1)])
	}
}

func BenchmarkContains(b *testing.B) {
	db, ips := benchDB(b, benchN)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.Contains(ips[i&(len(ips)-1)])
	}
}

func BenchmarkContainsMiss(b *testing.B) {
	db, _ := benchDB(b, benchN)
	// 203.0.113.x is not in the tree.
	miss := make([]netip.Addr, 256)
	for i := range miss {
		miss[i] = netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.Contains(miss[i&(len(miss)-1)])
	}
}

func BenchmarkLookupParallel(b *testing.B) {
	db, ips := benchDB(b, benchN)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, _, _, _ = db.LookupProvider(ips[i&(len(ips)-1)])
			i++
		}
	})
}

// Build throughput: networks inserted per second.
func BenchmarkBuild(b *testing.B) {
	for _, n := range []int{50_000, 200_000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				entries := func(yield func(Entry, error) bool) {
					for j := 0; j < n; j++ {
						a := byte(1 + (j>>16)&0x3f)
						bb := byte((j >> 8) & 0xff)
						c := byte(j & 0xff)
						p := netip.PrefixFrom(netip.AddrFrom4([4]byte{a, bb, c, 0}), 24)
						yield(Entry{Network: p, Record: Record{Provider: "aws", Region: "us-east-1", Services: []string{"EC2"}}}, nil)
					}
				}
				var buf bytes.Buffer
				if _, err := Build(entries, &buf, BuildOptions{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
