package attribution

import (
	"net/netip"
	"sort"
	"time"

	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// MMDB record keys. Kept short: each key string is stored once in the data
// section, but across a large tree it adds up.
const (
	keyProvider   = "provider"
	keyRegion     = "region"
	keyServices   = "services"
	keyCategories = "categories"
	keyIPv6       = "ipv6"
	keySource     = "source"
	keySyncedAt   = "synced_at"
	keyExt        = "ext"
)

// storedRecord mirrors the on-disk MMDB schema for decoding via the reader.
// SyncedAt is a unix epoch (uint64) on disk; Record exposes it as time.Time.
// Ext is map<string,string> so nginx (which can only read string leaves) and
// every other consumer see the same shape.
type storedRecord struct {
	Provider   string            `maxminddb:"provider"`
	Region     string            `maxminddb:"region"`
	Services   []string          `maxminddb:"services"`
	Categories []string          `maxminddb:"categories"`
	IPv6       bool              `maxminddb:"ipv6"`
	Source     string            `maxminddb:"source"`
	SyncedAt   uint64            `maxminddb:"synced_at"`
	Ext        map[string]string `maxminddb:"ext"`
}

// toRecord converts a decoded on-disk record into the public Record.
func (s storedRecord) toRecord() Record {
	var syncedAt time.Time
	if s.SyncedAt > 0 {
		syncedAt = time.Unix(int64(s.SyncedAt), 0).UTC()
	}
	return Record{
		Provider:   s.Provider,
		Region:     s.Region,
		Services:   s.Services,
		Categories: s.Categories,
		IPv6:       s.IPv6,
		Source:     s.Source,
		SyncedAt:   syncedAt,
		Ext:        s.Ext,
	}
}

// toMMDB builds the mmdbtype.Map written into the tree for one network. ipv6 is
// derived from the network at build time rather than trusted from the plugin.
func toMMDB(r Record, ipv6 bool) mmdbtype.Map {
	services := make(mmdbtype.Slice, 0, len(r.Services))
	for _, s := range dedupeSorted(r.Services) {
		services = append(services, mmdbtype.String(s))
	}

	ext := make(mmdbtype.Map, len(r.Ext))
	for k, v := range r.Ext {
		if v == "" {
			continue // don't pay to store empty specialization values
		}
		ext[mmdbtype.String(k)] = mmdbtype.String(v)
	}

	var synced uint64
	if !r.SyncedAt.IsZero() {
		if u := r.SyncedAt.Unix(); u > 0 {
			synced = uint64(u)
		}
	}

	m := mmdbtype.Map{
		keyProvider: mmdbtype.String(r.Provider),
		keyRegion:   mmdbtype.String(r.Region),
		keyServices: services,
		keyIPv6:     mmdbtype.Bool(ipv6),
		keySource:   mmdbtype.String(r.Source),
		keySyncedAt: mmdbtype.Uint64(synced),
		keyExt:      ext,
	}
	// Only carry categories when present, so pure-cloud records stay unchanged.
	if cats := dedupeSorted(r.Categories); len(cats) > 0 {
		cs := make(mmdbtype.Slice, len(cats))
		for i, c := range cats {
			cs[i] = mmdbtype.String(c)
		}
		m[keyCategories] = cs
	}
	return m
}

// isV6Network reports whether a prefix should be recorded as IPv6. v4-mapped
// ranges are treated as v4.
func isV6Network(p netip.Prefix) bool {
	return p.Addr().Is6() && !p.Addr().Is4In6()
}

// dedupeSorted returns the unique, sorted elements of in. Sorting makes records
// canonical so identical service sets hash to one data-section entry.
func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return in
	}
	cp := append([]string(nil), in...)
	sort.Strings(cp)
	out := cp[:0]
	var last string
	for i, s := range cp {
		if i == 0 || s != last {
			out = append(out, s)
			last = s
		}
	}
	return out
}
