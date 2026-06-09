package attribution

import (
	"iter"
	"net/netip"
	"sort"
	"strconv"

	"go4.org/netipx"
)

// Ext keys stamped by ASN enrichment (and the iptoasn plugin). They live in
// ext rather than the stable core because ASN is BGP-derived enrichment, not
// something the provider feeds assert — and ext strings are nginx-reachable.
const (
	ExtASN   = "asn"    // origin AS number, decimal: "16509"
	ExtASOrg = "as_org" // AS description: "AMAZON-02"
)

// ASNRange is one row of a BGP-derived IP->origin-AS table: an inclusive
// address range and the autonomous system that announces it.
type ASNRange struct {
	First, Last netip.Addr
	ASN         uint32
	Org         string
}

// ASNTable indexes ASNRanges for the interval lookups EnrichASN performs.
// NewASNTable normalizes rows into strictly non-overlapping form (the binary
// search in enrichEntry depends on it), so arbitrary input is safe. v4 and v6
// rows are kept separate so a search never compares across families.
type ASNTable struct {
	v4, v6 []ASNRange
}

// NewASNTable sorts and coalesces rows into a searchable table. Rows with
// invalid or mixed-family bounds are dropped; v4-mapped bounds are unmapped to
// native v4; overlaps and adjacent same-AS rows are normalized away (see
// CoalesceASNRanges).
func NewASNTable(rows []ASNRange) *ASNTable {
	t := &ASNTable{}
	for _, r := range rows {
		r.First, r.Last = r.First.Unmap(), r.Last.Unmap()
		if !r.First.IsValid() || !r.Last.IsValid() ||
			r.First.Is4() != r.Last.Is4() || r.First.Compare(r.Last) > 0 {
			continue
		}
		if r.First.Is4() {
			t.v4 = append(t.v4, r)
		} else {
			t.v6 = append(t.v6, r)
		}
	}
	t.v4 = CoalesceASNRanges(t.v4)
	t.v6 = CoalesceASNRanges(t.v6)
	return t
}

// CoalesceASNRanges sorts rows by First and normalizes them into a strictly
// non-overlapping, minimal set: a row overlapping its predecessor is clamped
// to start after it (first row wins, and a fully-contained row is dropped),
// and adjacent rows announcing the same ASN+Org are merged — iptoasn splits
// ranges where only the country code (a field we drop) changes, so merging
// shrinks both the enrichment table and a standalone ASN database. The input
// slice is reordered and its backing array reused.
func CoalesceASNRanges(rows []ASNRange) []ASNRange {
	sort.Slice(rows, func(i, j int) bool { return rows[i].First.Compare(rows[j].First) < 0 })
	out := rows[:0]
	for _, r := range rows {
		if len(out) == 0 {
			out = append(out, r)
			continue
		}
		prev := &out[len(out)-1]
		sameFamily := prev.Last.Is4() == r.First.Is4()
		if sameFamily && r.First.Compare(prev.Last) <= 0 { // overlap: first row wins
			next := prev.Last.Next()
			if !next.IsValid() || next.Compare(r.Last) > 0 {
				continue // fully contained in prev: drop
			}
			r.First = next
		}
		if sameFamily && prev.ASN == r.ASN && prev.Org == r.Org && prev.Last.Next() == r.First {
			prev.Last = r.Last // adjacent same-AS announcements: merge
			continue
		}
		out = append(out, r)
	}
	return out
}

// Len reports the number of usable rows in the table.
func (t *ASNTable) Len() int { return len(t.v4) + len(t.v6) }

// EnrichASN stamps each entry's ext with the origin AS that announces it
// (ExtASN/ExtASOrg), splitting an entry at announcement boundaries: a cloud
// CIDR spanning two ASNs (e.g. an AWS block partly announced by AS16509 and
// partly by AS8987 GovCloud) is emitted once per announcement, plus unstamped
// pieces for any unannounced gaps. Entries no announcement touches pass
// through unchanged, as do stream errors.
func EnrichASN(entries iter.Seq2[Entry, error], table *ASNTable) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		for e, err := range entries {
			if err != nil {
				if !yield(e, err) {
					return
				}
				continue
			}
			if !enrichEntry(e, table, yield) {
				return
			}
		}
	}
}

// enrichEntry intersects one entry with the table and yields the resulting
// pieces. It returns false if the consumer asked to stop.
func enrichEntry(e Entry, t *ASNTable, yield func(Entry, error) bool) bool {
	// Normalize exactly as Build will, so v4-mapped entries match the v4 table.
	// A malformed 4-in-6 super-range passes through untouched; Build skips it.
	network, ok := normalizePrefix(e.Network)
	if !ok {
		return yield(e, nil)
	}
	rows := t.v6
	if network.Addr().Is4() {
		rows = t.v4
	}
	r := netipx.RangeOfPrefix(network)
	lo, hi := r.From(), r.To()

	// First row that could overlap: non-overlapping rows sorted by First are
	// also sorted by Last, so binary search on Last finds the earliest candidate.
	i := sort.Search(len(rows), func(i int) bool { return rows[i].Last.Compare(lo) >= 0 })
	if i == len(rows) || rows[i].First.Compare(hi) > 0 {
		e.Network = network
		return yield(e, nil) // nothing announces any of it: pass through
	}

	cur := lo
	for ; i < len(rows) && rows[i].First.Compare(hi) <= 0; i++ {
		ovLo, ovHi := maxAddr(rows[i].First, cur), minAddr(rows[i].Last, hi)
		if ovLo.Compare(ovHi) > 0 {
			continue
		}
		if cur.Compare(ovLo) < 0 { // unannounced gap before this row
			if !yieldRange(e, cur, ovLo.Prev(), nil, yield) {
				return false
			}
		}
		if !yieldRange(e, ovLo, ovHi, &rows[i], yield) {
			return false
		}
		if ovHi.Compare(hi) >= 0 {
			return true
		}
		cur = ovHi.Next()
	}
	return yieldRange(e, cur, hi, nil, yield) // trailing unannounced gap
}

// yieldRange emits [first,last] as CIDR-aligned entries carrying e's record,
// with row's ASN stamped into a copied ext map when row is non-nil.
func yieldRange(e Entry, first, last netip.Addr, row *ASNRange, yield func(Entry, error) bool) bool {
	rec := e.Record
	if row != nil {
		ext := make(map[string]string, len(rec.Ext)+2)
		for k, v := range rec.Ext {
			ext[k] = v
		}
		ext[ExtASN] = strconv.FormatUint(uint64(row.ASN), 10)
		if row.Org != "" {
			ext[ExtASOrg] = row.Org
		}
		rec.Ext = ext
	}
	for _, p := range netipx.IPRangeFrom(first, last).Prefixes() {
		if !yield(Entry{Network: p, Record: rec}, nil) {
			return false
		}
	}
	return true
}

func minAddr(a, b netip.Addr) netip.Addr {
	if a.Compare(b) <= 0 {
		return a
	}
	return b
}

func maxAddr(a, b netip.Addr) netip.Addr {
	if a.Compare(b) >= 0 {
		return a
	}
	return b
}
