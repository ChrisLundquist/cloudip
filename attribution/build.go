package attribution

import (
	"fmt"
	"io"
	"iter"
	"net"
	"net/netip"
	"sort"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// DatabaseType is stamped into the MMDB metadata. It must NOT start with
// "GeoIP" (reserved + MaxMind trademark).
const DatabaseType = "Cloud-Attribution"

// BuildOptions tunes the output database. The zero value is usable.
type BuildOptions struct {
	// RecordSize is 24, 28, or 32. 28 is a good default. Zero means 28.
	RecordSize int
	// Description is the localized DB description. Defaults to a generic en string.
	Description map[string]string
	// BuildEpoch, if non-zero, is recorded so /version and the warehouse
	// partition can agree on which feed produced this file.
	BuildEpoch uint64
}

// BuildStats reports how a build went: networks inserted and networks skipped
// because the tree rejected them (e.g. aliased 6to4/Teredo ranges a feed
// occasionally lists). Skips are surfaced, never silent.
type BuildStats struct {
	Inserted int
	Skipped  int
}

// Build consumes normalized entries and writes a Cloud-Attribution MMDB to out.
// Overlapping prefixes union their Services (see mergeRecords) rather than
// clobber. An error from the entries iterator aborts the build; a per-network
// insert rejection is counted as a skip rather than failing the whole run,
// unless nothing at all could be inserted.
func Build(entries iter.Seq2[Entry, error], out io.Writer, opts BuildOptions) (BuildStats, error) {
	recordSize := opts.RecordSize
	if recordSize == 0 {
		recordSize = 28
	}
	desc := opts.Description
	if desc == nil {
		desc = map[string]string{"en": "Cloud provider IP attribution"}
	}

	treeOpts := mmdbwriter.Options{
		DatabaseType: DatabaseType,
		Description:  desc,
		IPVersion:    6, // a v6 tree holds v4-mapped ranges too
		RecordSize:   recordSize,
		// Cloud feeds occasionally publish otherwise-reserved ranges (test nets,
		// bot/CDN edges). We attribute exactly what the provider claims, so don't
		// let mmdbwriter reject inserts into reserved space.
		IncludeReservedNetworks: true,
	}
	if opts.BuildEpoch != 0 {
		treeOpts.BuildEpoch = int64(opts.BuildEpoch)
	}

	tree, err := mmdbwriter.New(treeOpts)
	if err != nil {
		return BuildStats{}, fmt.Errorf("new mmdb tree: %w", err)
	}

	var stats BuildStats
	for e, err := range entries {
		if err != nil {
			return stats, fmt.Errorf("entry stream: %w", err)
		}
		if !e.Network.IsValid() {
			return stats, fmt.Errorf("invalid network in entry for provider %q", e.Record.Provider)
		}
		e.Record.IPv6 = isV6Network(e.Network)
		rec := toMMDB(e.Record, e.Record.IPv6)
		ipnet := prefixToIPNet(e.Network)
		if err := tree.InsertFunc(ipnet, mergeRecords(rec)); err != nil {
			// Aliased ranges (6to4/Teredo) and similar structural rejects: skip
			// the single network rather than failing the whole feed.
			stats.Skipped++
			continue
		}
		stats.Inserted++
	}
	if stats.Inserted == 0 {
		return stats, fmt.Errorf("no networks inserted (%d skipped)", stats.Skipped)
	}

	if _, err := tree.WriteTo(out); err != nil {
		return stats, fmt.Errorf("write mmdb: %w", err)
	}
	return stats, nil
}

// mergeRecords returns an inserter that unions the services array (and ext map)
// when a network collides with one already in the tree, and otherwise writes
// the incoming record. AWS lists the same CIDR once per owning service, so this
// is what turns three single-service inserts into one multi-service record.
func mergeRecords(incoming mmdbtype.Map) inserter.Func {
	return func(existing mmdbtype.DataType) (mmdbtype.DataType, error) {
		cur, ok := existing.(mmdbtype.Map)
		if !ok {
			return incoming, nil // empty slot or non-map: take the incoming record
		}
		// A different provider claiming the same prefix: keep the first writer
		// rather than fuse two providers into one inconsistent record (e.g. an aws
		// record carrying a gcp service). Build order is deterministic (plugins
		// sorted by name), so the winner is stable. provider stays scalar; revisit
		// if multi-provider ownership (BYOIP/CDN) becomes common.
		if !sameString(cur[keyProvider], incoming[keyProvider]) {
			return cur, nil
		}
		merged := cur.Copy().(mmdbtype.Map)
		merged[keyServices] = unionSlices(cur[keyServices], incoming[keyServices])
		merged[keyExt] = unionExt(cur[keyExt], incoming[keyExt])
		merged[keySyncedAt] = maxUint64(cur[keySyncedAt], incoming[keySyncedAt])
		return merged, nil
	}
}

// sameString reports whether two mmdbtype values are equal Strings.
func sameString(a, b mmdbtype.DataType) bool {
	as, aok := a.(mmdbtype.String)
	bs, bok := b.(mmdbtype.String)
	return aok && bok && as == bs
}

// maxUint64 returns the larger of two mmdbtype.Uint64 values (0 for non-uints),
// so a merge keeps the freshest feed timestamp regardless of insert order.
func maxUint64(a, b mmdbtype.DataType) mmdbtype.Uint64 {
	av, _ := a.(mmdbtype.Uint64)
	bv, _ := b.(mmdbtype.Uint64)
	if bv > av {
		return bv
	}
	return av
}

// unionSlices merges two mmdbtype.Slice service arrays into a sorted, de-duped
// slice. Non-slice inputs are tolerated (treated as empty).
func unionSlices(a, b mmdbtype.DataType) mmdbtype.Slice {
	seen := map[mmdbtype.String]struct{}{}
	add := func(d mmdbtype.DataType) {
		s, ok := d.(mmdbtype.Slice)
		if !ok {
			return
		}
		for _, el := range s {
			if str, ok := el.(mmdbtype.String); ok {
				seen[str] = struct{}{}
			}
		}
	}
	add(a)
	add(b)

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	out := make(mmdbtype.Slice, len(keys))
	for i, k := range keys {
		out[i] = mmdbtype.String(k)
	}
	return out
}

// unionExt merges two ext maps; existing keys win only when incoming is empty,
// otherwise incoming values take precedence (newer feed).
func unionExt(a, b mmdbtype.DataType) mmdbtype.Map {
	out := mmdbtype.Map{}
	if m, ok := a.(mmdbtype.Map); ok {
		for k, v := range m {
			out[k] = v
		}
	}
	if m, ok := b.(mmdbtype.Map); ok {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// prefixToIPNet converts a netip.Prefix to the *net.IPNet that mmdbwriter
// expects. mmdbwriter canonicalizes the network address itself, so callers need
// not pre-mask the prefix.
func prefixToIPNet(p netip.Prefix) *net.IPNet {
	addr := p.Addr()
	bits := p.Bits()
	// Unmap v4-in-v6 (e.g. ::ffff:1.2.3.0/120) to native IPv4, else mmdbwriter
	// rejects it as an insert into the aliased ::ffff:0:0/96 network.
	if addr.Is4In6() {
		addr = addr.Unmap()
		bits -= 96
	}
	if addr.Is4() {
		return &net.IPNet{
			IP:   net.IP(addr.AsSlice()),
			Mask: net.CIDRMask(bits, 32),
		}
	}
	return &net.IPNet{
		IP:   net.IP(addr.AsSlice()),
		Mask: net.CIDRMask(bits, 128),
	}
}
