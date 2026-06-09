# Benchmarks

Lookups are the hot path, so they're the focus. Headline: **our reader matches or
beats [`rezmoss/go-cloudip`](https://github.com/rezmoss/go-cloudip) (a cidranger
trie holding pre-parsed Go structs in memory) on the comparable operations — while
serving 24× more data and keeping the database on disk (mmap'd, shareable across
processes and with nginx) instead of duplicated on every process's heap.**

All numbers: Apple M-series (`darwin/arm64`, 18 logical CPUs), Go 1.26, `-benchmem`.
Reproduce the head-to-head with `cd bench && go test -bench . -benchmem`.

## Head-to-head vs go-cloudip

Both sides resolve the **same real cloud IPs**: go-cloudip uses its embedded
dataset (`WithOffline`, 15,234 ranges across 4 providers); ours uses a database
built from the live rezmoss-all feed (**367,001 networks across 19 providers** —
24× larger).

| operation | ours | go-cloudip | result |
|---|---|---|---|
| membership — "is this a cloud IP?" | **43 ns/op, 0 B, 0 allocs** | 81 ns/op, 15 B, 2 allocs | **1.9× faster, allocation-free** |
| provider lookup (indexed) | **51 ns/op, 0 B, 0 allocs** | 78 ns/op, 15 B, 2 allocs | **1.5× faster, allocation-free** |
| provider lookup (decode, no index) | 161 ns/op, 22 B, 0 allocs | 78 ns/op, 15 B, 2 allocs | slower, but zero extra memory |
| full record (provider+region+services+ext) | 293 ns/op, 171 B, 3 allocs | n/a | go-cloudip returns less |

- **`Contains` (membership)** is a pure search-tree traversal with no decode, so
  it's allocation-free and beats cidranger's `ContainingNetworks`, which allocates
  a slice of matches and linear-scans for the most specific.
- **`LookupProvider`** decodes provider+region from the MMDB on each call (161 ns).
  Calling `db.BuildIndex()` once pre-decodes each distinct record into an in-memory
  `offset → {provider,region}` map, dropping that to **51 ns and 0 allocs** — faster
  than go-cloudip while still keeping the full database on disk. The server exposes
  this via `serve --index` and `GET /v1/provider/{ip}`.

The tradeoff is honest: go-cloudip loads every range into Go memory, so its
"lookup" is a trie-find plus a struct copy with no decode. We keep the compact
binary on disk and decode (or index) — which is what makes the same file usable by
nginx's geoip2 module and shareable across processes without per-process heap.

## Reader micro-benchmarks (this module)

Synthetic 200k-network database, `go test ./attribution -bench Lookup -benchmem`:

| benchmark | ns/op | allocs |
|---|---|---|
| `Contains` (hit) | 58 | 0 |
| `Contains` (miss) | 5.5 | 0 |
| `LookupProvider` (decode) | 233 | 1 |
| `LookupFull` | 509 | 7 |
| `LookupProvider` parallel (18 cores) | 24 | 1 |

Lookups scale cleanly across cores (the reader is read-only over an mmap), so
parallel throughput is roughly per-core latency ÷ cores.

## Build throughput

`go test ./attribution -bench BenchmarkBuild`:

| networks | time | rate |
|---|---|---|
| 50,000 | 124 ms | ~400k networks/s |
| 200,000 | 428 ms | ~470k networks/s |

A full rezmoss-all build (~370k networks) lands well under a second of tree
construction; the wall-clock of a real `cloudattr build` is dominated by fetching
the feed, not building the database.
