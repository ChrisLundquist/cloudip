package attribution

import (
	"fmt"
	"iter"
	"net/netip"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// DB is a read-only handle to a Cloud-Attribution MMDB. The underlying reader
// mmaps the file, so a single DB is safe to share across goroutines: open once
// at startup, look up concurrently.
type DB struct {
	r *maxminddb.Reader
	// idx, when built, maps a record's data-section offset to its pre-decoded
	// identity, so LookupProvider can skip the per-lookup MMDB decode. Records are
	// deduplicated in the MMDB, so this holds one entry per distinct record.
	idx map[uint64]miniRecord
}

// Open opens the MMDB at path. It does not validate the DatabaseType; use Verify
// or check Metadata().DatabaseType if you need to reject foreign databases.
func Open(path string) (*DB, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open mmdb %q: %w", path, err)
	}
	return &DB{r: r}, nil
}

// OpenBytes opens an MMDB held in memory (handy for tests).
func OpenBytes(b []byte) (*DB, error) {
	r, err := maxminddb.OpenBytes(b)
	if err != nil {
		return nil, fmt.Errorf("open mmdb bytes: %w", err)
	}
	return &DB{r: r}, nil
}

// Close releases the underlying file mapping.
func (d *DB) Close() error { return d.r.Close() }

// Validate checks that an opened database is actually a Cloud-Attribution MMDB
// with data, rejecting wrong-type or structurally-empty files that nonetheless
// parsed. Callers loading a file produced elsewhere (e.g. a hot reload of a
// copied file) should Validate before trusting it.
func (d *DB) Validate() error {
	md := d.r.Metadata
	if md.DatabaseType != DatabaseType {
		return fmt.Errorf("unexpected database_type %q, want %q", md.DatabaseType, DatabaseType)
	}
	if md.NodeCount == 0 {
		return fmt.Errorf("database has no nodes")
	}
	return nil
}

// OpenValidated opens path and verifies it is a non-empty Cloud-Attribution
// database, closing it and returning an error otherwise. This is the safe way to
// load a file that may have been partially copied or swapped underneath us.
func OpenValidated(path string) (*DB, error) {
	db, err := Open(path)
	if err != nil {
		return nil, err
	}
	if err := db.Validate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("validate %q: %w", path, err)
	}
	return db, nil
}

// Lookup returns the attribution record for ip. found is false (with a nil
// error) when ip is in no known cloud range. The returned Record carries the
// matched network (see Record.Network for its exact semantics); a v4-mapped
// query (::ffff:a.b.c.d) reports it as native IPv4, while 6to4/Teredo queries
// report it in the queried (aliased) address space.
func (d *DB) Lookup(ip netip.Addr) (rec Record, found bool, err error) {
	res := d.r.Lookup(ip)
	if err := res.Err(); err != nil {
		return Record{}, false, fmt.Errorf("lookup %s: %w", ip, err)
	}
	if !res.Found() {
		return Record{}, false, nil
	}
	var sr storedRecord
	if err := res.Decode(&sr); err != nil {
		return Record{}, false, fmt.Errorf("decode record for %s: %w", ip, err)
	}
	rec = sr.toRecord()
	rec.Network = unmapPrefix(res.Prefix())
	return rec, true, nil
}

// unmapPrefix canonicalizes a v4-in-v6 matched prefix (::ffff:a.b.c.0/123) to
// native IPv4 (a.b.c.0/27), so a v4-mapped query reports the same network as
// the equivalent plain-v4 query. Other prefixes pass through unchanged.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p
}

// Contains reports whether ip falls in any known network. It decodes nothing —
// just a search-tree traversal — so it's the fastest "is this a cloud/known IP?"
// check, with zero allocations.
func (d *DB) Contains(ip netip.Addr) bool {
	return d.r.Lookup(ip).Found()
}

// miniRecord decodes only the attribution identity, skipping the heavier
// services/categories/ext fields.
type miniRecord struct {
	Provider string `maxminddb:"provider"`
	Region   string `maxminddb:"region"`
}

// LookupProvider returns just the provider and region for ip, skipping the
// services/categories/ext decode. Use it when you only need attribution identity
// (which cloud, which region) rather than the full record — it's markedly faster
// and allocates far less than Lookup. If BuildIndex has been called it skips the
// MMDB decode entirely (an in-memory offset lookup).
func (d *DB) LookupProvider(ip netip.Addr) (provider, region string, found bool, err error) {
	res := d.r.Lookup(ip)
	if err := res.Err(); err != nil {
		return "", "", false, fmt.Errorf("lookup %s: %w", ip, err)
	}
	if !res.Found() {
		return "", "", false, nil
	}
	if d.idx != nil {
		m := d.idx[uint64(res.Offset())]
		return m.Provider, m.Region, true, nil
	}
	var m miniRecord
	if err := res.Decode(&m); err != nil {
		return "", "", false, fmt.Errorf("decode provider for %s: %w", ip, err)
	}
	return m.Provider, m.Region, true, nil
}

// BuildIndex pre-decodes every record's provider/region into an in-memory map
// keyed by data-section offset, so subsequent LookupProvider calls skip the MMDB
// decode (trading a few MB of heap for ~2-3x faster identity lookups). Call it
// once after Open, before sharing the DB across goroutines; it is not safe to run
// concurrently with lookups. Idempotent.
func (d *DB) BuildIndex() error {
	idx := make(map[uint64]miniRecord)
	for res := range d.r.Networks() {
		if err := res.Err(); err != nil {
			return fmt.Errorf("build index: %w", err)
		}
		off := uint64(res.Offset())
		if _, ok := idx[off]; ok {
			continue // record already decoded (offsets are deduplicated)
		}
		var m miniRecord
		if err := res.Decode(&m); err != nil {
			return fmt.Errorf("build index decode: %w", err)
		}
		idx[off] = m
	}
	d.idx = idx
	return nil
}

// LookupString parses ip and looks it up.
func (d *DB) LookupString(ip string) (Record, bool, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Record{}, false, fmt.Errorf("parse ip %q: %w", ip, err)
	}
	return d.Lookup(addr)
}

// BuildTime reports the build epoch stamped into the MMDB metadata, used by the
// /version endpoint and the warehouse partition so they agree.
func (d *DB) BuildTime() time.Time { return d.r.Metadata.BuildTime() }

// Metadata exposes the raw MMDB metadata (DatabaseType, RecordSize, ...).
func (d *DB) Metadata() maxminddb.Metadata { return d.r.Metadata }

// NetworkRecord pairs a network with its decoded record during a tree walk.
type NetworkRecord struct {
	Network netip.Prefix
	Record  Record
}

// Networks iterates every network in the tree that has data, in tree order.
// This backs CSV export and Verify. The iterator yields an error and stops on
// the first decode failure.
func (d *DB) Networks() iter.Seq2[NetworkRecord, error] {
	return func(yield func(NetworkRecord, error) bool) {
		for res := range d.r.Networks() {
			if err := res.Err(); err != nil {
				yield(NetworkRecord{}, err)
				return
			}
			var sr storedRecord
			if err := res.Decode(&sr); err != nil {
				yield(NetworkRecord{}, fmt.Errorf("decode %s: %w", res.Prefix(), err))
				return
			}
			if !yield(NetworkRecord{Network: res.Prefix(), Record: sr.toRecord()}, nil) {
				return
			}
		}
	}
}
