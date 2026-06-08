# Cloud IP Attribution — Design Sketch

GeoIP-style attribution for cloud providers. Per-provider plugins normalize published
IP ranges into a single MMDB; a thin reader library is wrapped by gRPC / HTTP / CLI,
and the same MMDB is consumed directly by nginx via `ngx_http_geoip2_module`.

```
provider feeds            build time                     serve time
─────────────────         ──────────────                 ────────────────────
rezmoss repo  ─┐                                      ┌─ gRPC server
AWS json      ─┼─ plugins ─> normalized ─> mmdbwriter ─┼─ HTTP server
Azure tags    ─┤             entries        (Go)      ─┼─ CLI
GCP json      ─┘                │                      ├─ nginx (geoip2 module)
                               .mmdb  ──> CSV export ──┴─ Presto/Trino
```

Two-binary split: a **builder** (Go, uses mmdbwriter) and a **server** (Go or Rust,
reader-only). They share only the `.mmdb` file and the record schema.

---

## 1. Licensing summary

| Component | License | Notes |
|---|---|---|
| MMDB format spec | CC BY-SA 3.0 | You implement it; you don't redistribute the spec. Non-issue. |
| libmaxminddb (C reader) | Apache 2.0 | |
| mmdbwriter (Go writer) | Apache 2.0 / MIT | Use this for the build pipeline. |
| maxminddb-golang (Go reader) | ISC | |
| maxminddb (Rust reader) | ISC/MIT | Mature. |
| maxminddb-writer (Rust) | — | v0.1.x, early; prefer Go for writing. |
| ngx_http_geoip2_module | BSD-2 | Reads any MMDB. |
| rezmoss/cloud-provider-ip-addresses | CC0 | Public domain. Upstream provider terms still apply. |

**Gotcha:** `DatabaseType` and branding must not start with `GeoIP` (reserved + trademark).
Use `Cloud-Attribution`.

---

## 2. Record schema

Every network maps to a record with a **stable core** (uniformly queryable across all
providers) plus a **provider-namespaced map** for specialization.

```
{
  "provider":  "aws",                 // utf8_string  — which plugin produced this
  "region":    "us-east-1",           // utf8_string  — "" if provider gives none (e.g. GCP)
  "services":  ["EC2", "S3"],         // array<utf8>  — accumulates on overlapping prefixes
  "ipv6":      false,                 // boolean
  "source":    "ip-ranges.json",      // utf8_string  — provenance
  "synced_at": 1718000000,            // uint64       — unix epoch of the feed
  "ext": {                            // map          — provider-specific specialization
    "network_border_group": "us-east-1",
    "scope": "..."
  }
}
```

Design notes:
- **`services` is an array, not a scalar.** AWS lists the same CIDR once per owning
  service. A scalar would clobber on the second insert. See the merge inserter below.
- **`ext` is the specialization escape hatch.** Azure stashes `systemService`/`platform`,
  GCP stashes almost nothing, AWS stashes `network_border_group`. The core stays clean.
- Keep keys short; they're stored once in the MMDB data section but it adds up.

---

## 3. Plugin interface (Go)

A plugin's only job: fetch a provider's published data and yield normalized entries.
It knows nothing about MMDB, gRPC, or merging.

```go
package attribution

import (
    "context"
    "io"
    "iter"
    "net/netip"
    "time"
)

// Record is the normalized, provider-agnostic attribution payload for one network.
type Record struct {
    Provider  string
    Region    string
    Services  []string
    Source    string
    SyncedAt  time.Time
    Ext       map[string]any // provider-specific specialization
}

type Entry struct {
    Network netip.Prefix
    Record  Record
}

// Source abstracts where raw bytes come from: a rezmoss path, a provider URL,
// or a local cache file. Lets tests inject fixtures and lets ops pin to rezmoss.
type Source interface {
    Open(ctx context.Context, ref string) (io.ReadCloser, error)
}

// Plugin is implemented once per cloud provider.
type Plugin interface {
    Name() string                              // "aws", "azure", "gcp"
    // Refs returns the source references this plugin needs (URLs or rezmoss paths).
    Refs() []string
    // Parse normalizes already-fetched bytes into entries. Pure + testable.
    Parse(ref string, r io.Reader) iter.Seq2[Entry, error]
}

// Registry — plugins self-register via init().
var registry = map[string]Plugin{}

func Register(p Plugin) { registry[p.Name()] = p }
func Plugins() map[string]Plugin { return registry }
```

Splitting `Refs()`/`Parse()` from fetching means the builder controls IO (retries,
caching, choosing rezmoss vs. direct), and `Parse` stays a pure function over bytes —
trivial to unit-test against checked-in fixtures.

Example plugin skeleton:

```go
package aws

func init() { attribution.Register(plugin{}) }

type plugin struct{}

func (plugin) Name() string   { return "aws" }
func (plugin) Refs() []string { return []string{"aws/ip-ranges.json"} } // rezmoss-relative

func (plugin) Parse(ref string, r io.Reader) iter.Seq2[attribution.Entry, error] {
    return func(yield func(attribution.Entry, error) bool) {
        var doc struct {
            SyncToken  string `json:"syncToken"`
            Prefixes []struct {
                IPPrefix string `json:"ip_prefix"`
                Region   string `json:"region"`
                Service  string `json:"service"`
                NBG      string `json:"network_border_group"`
            } `json:"prefixes"`
            // (IPv6Prefixes handled symmetrically)
        }
        if err := json.NewDecoder(r).Decode(&doc); err != nil {
            yield(attribution.Entry{}, err)
            return
        }
        for _, p := range doc.Prefixes {
            pre, err := netip.ParsePrefix(p.IPPrefix)
            if err != nil { if !yield(attribution.Entry{}, err) { return }; continue }
            e := attribution.Entry{
                Network: pre,
                Record: attribution.Record{
                    Provider: "aws",
                    Region:   p.Region,
                    Services: []string{p.Service},
                    Source:   ref,
                    Ext:      map[string]any{"network_border_group": p.NBG},
                },
            }
            if !yield(e, nil) { return }
        }
    }
}
```

---

## 4. Builder — entries → .mmdb

The merge inserter is the important part: overlapping prefixes must **union their
services** rather than replace.

```go
import (
    "github.com/maxmind/mmdbwriter"
    "github.com/maxmind/mmdbwriter/mmdbtype"
)

func Build(entries iter.Seq2[Entry, error], out io.Writer) error {
    tree, err := mmdbwriter.New(mmdbwriter.Options{
        DatabaseType: "Cloud-Attribution", // NOT "GeoIP*"
        Description:  map[string]string{"en": "Cloud provider IP attribution"},
        IPVersion:    6,  // a v6 tree holds v4-mapped ranges too
        RecordSize:   28, // 24/28/32; 28 is a good default
    })
    if err != nil { return err }

    for e, err := range entries {
        if err != nil { return err }
        rec := toMMDB(e.Record)                 // Record -> mmdbtype.Map
        ipnet := netipPrefixToIPNet(e.Network)
        if err := tree.InsertFunc(ipnet, mergeServices(rec)); err != nil {
            return err
        }
    }
    _, err = tree.WriteTo(out)
    return err
}

// mergeServices returns an inserter.Func that unions the "services" array when a
// network collides with one already in the tree, and otherwise writes the record.
func mergeServices(incoming mmdbtype.Map) inserter.Func {
    return func(existing mmdbtype.DataType) (mmdbtype.DataType, error) {
        cur, ok := existing.(mmdbtype.Map)
        if !ok { return incoming, nil } // empty slot
        merged := cur.Copy().(mmdbtype.Map)
        merged["services"] = unionSlices(cur["services"], incoming["services"])
        // optionally merge ext, refresh synced_at, etc.
        return merged, nil
    }
}
```

`mmdbwriter` canonicalizes networks (e.g. `1.2.3.4/28` → the network address), so you
don't pre-normalize. For data-dedup it hashes record values, so identical records across
many prefixes cost one data-section entry.

---

## 5. Reader library

Tiny surface. mmap'd by the underlying reader; load once, share across goroutines.

```go
type DB struct{ r *maxminddb.Reader }

func Open(path string) (*DB, error) { /* maxminddb.Open(path) */ }

func (d *DB) Lookup(ip netip.Addr) (Record, bool, error) {
    var rec Record
    res := d.r.Lookup(ip)            // v2 API; v1 is Lookup(net.IP, &rec)
    if !res.Found() { return Record{}, false, nil }
    if err := res.Decode(&rec); err != nil { return Record{}, false, err }
    return rec, true, nil
}
```

Rust equivalent (reader is mature; serve here if you prefer Rust):

```rust
let reader = maxminddb::Reader::open_readfile("cloud.mmdb")?;
let rec: Record = reader.lookup(ip)?.decode()?;   // serde-derived struct
```

---

## 6. Wrapper interfaces

### gRPC

```proto
service CloudAttribution {
  rpc Lookup      (LookupRequest)        returns (Record);
  rpc BatchLookup (stream LookupRequest) returns (stream LookupResult);
}
message LookupRequest { string ip = 1; }
message Record {
  string provider = 1; string region = 2; repeated string services = 3;
  bool ipv6 = 4; string source = 5; int64 synced_at = 6;
  map<string,string> ext = 7;
}
message LookupResult { string ip = 1; Record record = 2; bool found = 3; }
```

### HTTP

```
GET /v1/lookup/{ip}        -> 200 {record} | 404
GET /v1/lookup?ip=...&ip=  -> 200 [{ip,found,record}, ...]   # batch
GET /healthz  GET /metrics  GET /version   # version = mmdb build_epoch
```

### CLI

```
cloudattr lookup 52.94.0.1                 # single
cloudattr lookup -f ips.txt --format json  # batch from file
cloudattr build --source rezmoss --out cloud.mmdb
cloudattr build --source direct  --out cloud.mmdb   # hit provider URLs
cloudattr export --in cloud.mmdb --format csv --out cloud.csv
cloudattr verify --in cloud.mmdb           # walk tree, validate
```

### nginx — no custom module

Point the existing `ngx_http_geoip2_module` at the same file. Your record keys become
nginx variables:

```nginx
geoip2 /etc/nginx/cloud.mmdb {
    auto_reload 60m;
    $cloud_provider provider;
    $cloud_region   region;
    $cloud_service  services 0;   # first element of the array
}

# example use
map $cloud_provider $is_cloud { default 0; ~. 1; }
log_format main '... cloud=$cloud_provider/$cloud_region';
```

---

## 7. CSV export for Presto/Trino

Walk the tree (mmdbwriter and the readers can iterate networks) and emit a row per
network. Emit **both** the CIDR and integer range bounds — range joins on integers are
the fastest pattern in Presto/Trino, while the CIDR stays human-readable.

```
network_cidr,start_ip_int,end_ip_int,provider,region,services,ipv6,synced_at
52.94.0.0/22,famarsh...,...,aws,us-east-1,"EC2,S3",false,1718000000
```

Join pattern:

```sql
SELECT e.*, c.provider, c.region
FROM events e
JOIN cloud_ranges c
  ON e.ip_int BETWEEN c.start_ip_int AND c.end_ip_int;
```

(For IPv6, use two 64-bit hi/lo columns or a `VARBINARY` and compare lexicographically.)

---

## 8. Build / sync pipeline

```
              ┌── --source rezmoss (default): consume CC0 per-provider files;
sync job ─────┤                               low maintenance, daily-updated upstream
 (cron/CI)    └── --source direct: plugins hit AWS/Azure/GCP URLs themselves;
                                    more control, you own the parsing churn
       │
       ├─ run enabled plugins -> entries
       ├─ Build() -> cloud.mmdb.tmp
       ├─ verify (walk + sanity counts; fail if CIDR count drops >X% vs last)
       └─ atomic rename -> cloud.mmdb ; servers auto_reload / SIGHUP
```

Ship two outputs each run: `cloud.mmdb` (serving) and `cloud.csv` (warehouse). Stamp the
build epoch into MMDB metadata so `/version` and the warehouse partition agree.

---

## 9. Open questions to resolve next

- **Reader version pinning** — maxminddb-golang v1 vs v2 have different `Lookup` APIs;
  pick before writing the server.
- **`ext` typing in MMDB** — keep it `map<string,string>` for nginx-friendliness, or
  allow nested types and accept that nginx can only reach string leaves?
- **Conflict policy across providers** — can two providers ever claim the same prefix
  (CDNs, BYOIP)? If so, decide whether `provider` becomes an array too.
- **Direct-mode trust** — if you parse provider feeds yourself, you inherit their schema
  changes. rezmoss absorbs that for you but adds a dependency. Hybrid default = rezmoss
  with a `direct` fallback per provider.
```
