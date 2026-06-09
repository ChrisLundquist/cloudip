// Package iptoasn normalizes the iptoasn.com IP->ASN table into attribution
// entries. The data is BGP-derived (built from RouteViews announcements) and
// public domain, refreshed hourly — which makes it the right source for origin
// ASN: provider feeds like AWS's ip-ranges.json carry no ASN at all, and the
// announcement reality (AS16509 vs the legacy AS14618/AS7224 space, AS8987
// GovCloud) only exists in BGP.
//
// Feed: https://iptoasn.com/data/ip2asn-combined.tsv.gz — TSV rows of
// `range_start range_end as_number country_code as_description`, v4 and v6 in
// one file, ranges inclusive and non-overlapping. Unrouted space is published
// as as_number 0 and skipped.
package iptoasn

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"iter"
	"net/netip"
	"strconv"
	"strings"

	"go4.org/netipx"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func init() { attribution.RegisterASN(Plugin{}) }

// Plugin implements attribution.Plugin for the iptoasn.com table.
type Plugin struct{}

func (Plugin) Name() string { return "iptoasn" }

// Refs is the offline/fixture/mirror path; DirectRefs is the live URL.
func (Plugin) Refs() []string { return []string{"iptoasn/ip2asn-combined.tsv"} }

// DirectURL is the canonical combined (v4+v6) table, gzipped.
const DirectURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

// DirectRefs returns the provider's own URL for direct fetches.
func (Plugin) DirectRefs() []string { return []string{DirectURL} }

// ParseTable decodes the TSV into ASNRanges, skipping unrouted (AS0) rows. It
// transparently inflates gzip input (sniffed by magic bytes), so it accepts
// the live .tsv.gz and plain-text fixtures alike. Org strings are interned:
// the table repeats each AS description once per announced range.
func ParseTable(r io.Reader) ([]attribution.ASNRange, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("gunzip ip2asn: %w", err)
		}
		defer gz.Close()
		br = bufio.NewReaderSize(gz, 64<<10)
	}

	var rows []attribution.ASNRange
	intern := map[string]string{}
	sc := bufio.NewScanner(br)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) < 3 {
			return nil, fmt.Errorf("ip2asn line %d: %d fields, want at least 3", line, len(fields))
		}
		asn, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("ip2asn line %d: as_number %q: %w", line, fields[2], err)
		}
		if asn == 0 {
			continue // unrouted space
		}
		first, err := netip.ParseAddr(fields[0])
		if err != nil {
			return nil, fmt.Errorf("ip2asn line %d: range_start: %w", line, err)
		}
		last, err := netip.ParseAddr(fields[1])
		if err != nil {
			return nil, fmt.Errorf("ip2asn line %d: range_end: %w", line, err)
		}
		var org string
		if len(fields) >= 5 {
			org = fields[4]
			if cached, ok := intern[org]; ok {
				org = cached
			} else {
				intern[org] = org
			}
		}
		rows = append(rows, attribution.ASNRange{First: first, Last: last, ASN: uint32(asn), Org: org})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read ip2asn: %w", err)
	}
	return rows, nil
}

// Parse normalizes the table into entries for a standalone ASN database: one
// entry per CIDR-aligned piece of each announced range, the ASN riding in ext
// (asn, as_org) so nginx and every other consumer can read it.
func (Plugin) Parse(ref string, r io.Reader) iter.Seq2[attribution.Entry, error] {
	return func(yield func(attribution.Entry, error) bool) {
		rows, err := ParseTable(r)
		if err != nil {
			yield(attribution.Entry{}, err)
			return
		}
		// One ext map per distinct ASN, shared across its ranges: entries are
		// read-only downstream and the MMDB dedups identical records anyway.
		exts := map[uint32]map[string]string{}
		for _, row := range rows {
			ext, ok := exts[row.ASN]
			if !ok {
				ext = map[string]string{attribution.ExtASN: strconv.FormatUint(uint64(row.ASN), 10)}
				if row.Org != "" {
					ext[attribution.ExtASOrg] = row.Org
				}
				exts[row.ASN] = ext
			}
			ipr := netipx.IPRangeFrom(row.First.Unmap(), row.Last.Unmap())
			if !ipr.IsValid() {
				if !yield(attribution.Entry{}, fmt.Errorf("ip2asn: invalid range %s-%s", row.First, row.Last)) {
					return
				}
				continue
			}
			for _, p := range ipr.Prefixes() {
				e := attribution.Entry{
					Network: p,
					Record: attribution.Record{
						Provider: "iptoasn",
						Source:   ref,
						Ext:      ext,
					},
				}
				if !yield(e, nil) {
					return
				}
			}
		}
	}
}
