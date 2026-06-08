# cloudip — Cloud IP Attribution

GeoIP-style attribution of IP networks to cloud providers. Per-provider plugins
normalize published IP ranges into a single MMDB (`DatabaseType:
Cloud-Attribution`); a thin reader library is wrapped by gRPC / HTTP / CLI, and
the **same** MMDB is consumed directly by nginx via `ngx_http_geoip2_module`.

```
provider feeds            build time                     serve time
─────────────────         ──────────────                 ────────────────────
rezmoss repo  ─┐                                      ┌─ gRPC server
AWS json      ─┼─ plugins ─> normalized ─> mmdbwriter ─┼─ HTTP server
Azure tags    ─┤             entries        (Go)      ─┼─ CLI
GCP json      ─┘                │                      ├─ nginx (geoip2 module)
                               .mmdb  ──> CSV export ──┴─ Presto/Trino
```

Coverage: the native `aws`/`azure`/`gcp` plugins parse providers' own feeds for
`--source direct`, but `--source rezmoss-all` consumes **every** provider the
rezmoss mirror tracks (~24: the big-three clouds plus Cloudflare, Fastly, Oracle,
Linode, DigitalOcean, Vultr, GitHub, Zoom, Atlassian, and assorted bot networks).

Two-binary split in spirit: a **builder** (`cloudattr build`, uses
[`mmdbwriter`](https://github.com/maxmind/mmdbwriter)) and a **reader/server**
(`cloudattr serve`, [`maxminddb-golang/v2`](https://github.com/oschwald/maxminddb-golang)).
They share only the `.mmdb` file and the record schema.

## Quick start

```sh
go build -o cloudattr ./cmd/cloudattr

# Build from the rezmoss CC0 mirror (default), or from provider URLs / fixtures:
./cloudattr build --source rezmoss     --out cloud.mmdb --csv cloud.csv  # aws/azure/gcp plugins
./cloudattr build --source rezmoss-all --out cloud.mmdb                  # ALL ~24 rezmoss providers
./cloudattr build --source direct      --out cloud.mmdb                  # hit AWS/Azure/GCP URLs
./cloudattr build --fixtures ./feeds   --out cloud.mmdb                  # offline, from local files

# --source rezmoss-all consumes the unified all_providers.json: aws, azure,
# googlecloud, cloudflare, fastly, oracle, linode, digitalocean, vultr, github,
# zoom, atlassian, and bot networks (~400k networks). Subset with --providers:
./cloudattr build --source rezmoss-all --providers aws,cloudflare,fastly --out edge.mmdb

# Query
./cloudattr lookup 52.94.0.1                      # single
./cloudattr lookup -f ips.txt --format json       # batch from file (or '-' for stdin)
./cloudattr verify --in cloud.mmdb                # walk + sanity counts
./cloudattr export --in cloud.mmdb --out cloud.csv

# Serve gRPC + HTTP (SIGHUP reloads an atomically-replaced file in place)
./cloudattr serve --in cloud.mmdb --http :8080 --grpc :9090
```

HTTP surface:

```
GET /v1/lookup/{ip}        -> 200 {record} | 404 | 400
GET /v1/lookup?ip=&ip=     -> 200 [{ip,found,record}, ...]   # batch
GET /healthz  GET /metrics  GET /version
```

## Record schema

Every network maps to a **stable core** (uniformly queryable across providers)
plus a provider-namespaced `ext` map for specialization. Stored in the MMDB as:

| key | type | notes |
|---|---|---|
| `provider` | utf8 | which plugin produced this (`aws`/`azure`/`gcp`) |
| `region` | utf8 | `""` when the provider gives none |
| `services` | array<utf8> | **unions** on overlapping prefixes (see below) |
| `ipv6` | boolean | derived from the network at build time |
| `source` | utf8 | provenance ref |
| `synced_at` | uint64 | unix epoch of the feed |
| `ext` | map<utf8,utf8> | provider-specific keys; strings so nginx can read them |

**`services` is an array, not a scalar.** AWS lists the same CIDR once per
owning service; the builder's merge inserter unions them rather than clobbering,
so `52.94.0.0/22` ends up `["AMAZON","EC2","S3"]`. `ext` is kept
`map<string,string>` so nginx (which can only reach string leaves) and every
other consumer see the same shape.

## Adding a provider plugin

Implement `attribution.Plugin` — `Name()`, `Refs()`, and a pure `Parse(ref, r)`
that yields normalized entries — then register it in `init()`. The builder owns
all IO (rezmoss vs. direct, retries, caching); `Parse` is a pure function over
bytes, trivially unit-tested against a checked-in fixture. Optionally implement
`DirectPlugin.DirectRefs()` to support `--source direct`; providers without a
stable direct URL (Azure) fall back to rezmoss automatically. See
`plugins/aws/aws.go`.

## nginx — no custom module

Point the existing `ngx_http_geoip2_module` at the same file; record keys become
nginx variables. See [`deploy/nginx-geoip2.conf`](deploy/nginx-geoip2.conf).

### Testing it with PROXY protocol

A self-contained config that takes the client IP from a PROXY-protocol header,
attributes it, and writes the attribution into both the log line and the
response — handy for verifying the MMDB end-to-end behind a real load balancer:

```nginx
load_module modules/ngx_http_geoip2_module.so;   # only if built as a dynamic module
events {}
http {
    geoip2 /path/to/cloud.mmdb {
        auto_reload 5m;
        # Look up the IP the upstream LB put in the PROXY header, not the TCP peer.
        $cloud_provider source=$proxy_protocol_addr provider;
        $cloud_region   source=$proxy_protocol_addr region;
        $cloud_service  source=$proxy_protocol_addr services 0;
    }

    map $cloud_provider $is_cloud { default 0; ~. 1; }

    log_format cloud '$proxy_protocol_addr cloud=$cloud_provider/$cloud_region '
                     'svc=$cloud_service is_cloud=$is_cloud "$request"';

    server {
        listen 8080 proxy_protocol;          # expect a PROXY v1/v2 header
        access_log /dev/stdout cloud;
        location = /whoami {
            default_type text/plain;
            return 200 '$cloud_provider $cloud_region $cloud_service\n';
        }
    }
}
```

Drive it with curl, spoofing a cloud client IP in the PROXY header:

```sh
curl --haproxy-protocol --haproxy-clientip 52.94.0.1 http://127.0.0.1:8080/whoami
# -> aws us-east-1 AMAZON
```

`internal/nginxtest` automates exactly this (skips cleanly when nginx, the
geoip2 module, or curl's `--haproxy-clientip` are unavailable):

```sh
go test ./internal/nginxtest/ -v
```

## Presto/Trino

`cloudattr export` emits both the human-readable CIDR and integer range bounds —
range joins on integers are the fastest pattern in Presto/Trino:

```sql
SELECT e.*, c.provider, c.region
FROM events e
JOIN cloud_ranges c ON e.ip_int BETWEEN c.start_ip_int AND c.end_ip_int;
```

IPv4 bounds fit a `BIGINT`; IPv6 bounds are full 128-bit decimals (use
`DECIMAL`/`VARBINARY`, or split hi/lo warehouse-side).

## Sync pipeline (ops)

`cloudattr build` is atomic: it writes `cloud.mmdb.tmp-*` in the target
directory, walks it to validate, refuses to publish if the network count drops
more than `--max-drop` (default 50%) versus the existing file, then renames into
place. Servers pick it up via SIGHUP (`cloudattr serve`) or nginx `auto_reload`.
The build epoch is stamped into MMDB metadata so `/version` and the warehouse
partition agree.

## Operational robustness (partial / corrupt data)

The pipeline is built to survive disk-full, crashes, and partial copies:

- **Atomic builds.** `cloudattr build` writes a temp file in the target
  directory, walks it to verify every record decodes, refuses to publish if the
  network count dropped more than `--max-drop`, **fsyncs**, then atomically
  renames into place (and fsyncs the directory). A disk-full or mid-build error
  surfaces before the rename and leaves the previous database untouched — never a
  truncated `cloud.mmdb`. CSV export is atomic the same way.
- **Fail-closed sync.** Any fetch/parse error aborts the whole build (no
  partial publish); the previous `cloud.mmdb` keeps serving and the next cron run
  retries. `--max-drop` (default 0.5) refuses a build that shrank too much vs the
  existing file; `--max-skip` (default 0.25) refuses one where too large a
  fraction of entries were skipped (malformed/aliased) even on a first build.
  Transient HTTP failures (network/5xx/429/408) are retried with backoff before
  giving up.
- **Validated loads.** `OpenValidated` (used by the server) rejects a file that
  isn't a non-empty `Cloud-Attribution` database, so a truncated or garbage file
  (e.g. an interrupted `scp`) is refused rather than served. A failed `Reload`
  keeps the currently-loaded good database serving.
- **⚠️ Deploy via atomic rename, never in-place overwrite.** The reader mmaps the
  file. Replacing it in place (`rsync --inplace`, `cp` over it) corrupts the
  running reader's memory. Always write to a temp file on the destination and
  `mv`/`rename` it into place (and `nginx auto_reload` / `SIGHUP` will pick it
  up). `cloudattr build` already does this locally.

## Implementation notes (resolved design open questions)

- **Reader version:** pinned to `maxminddb-golang/v2` (the `Lookup(ip).Decode()` API).
- **`ext` typing:** stored as `map<string,string>` so nginx can reach every leaf;
  empty values are dropped at build time.
- **Cross-provider conflicts:** `services` and `ext` union on overlapping prefixes;
  `provider`/`region` keep the first writer (build order is deterministic — plugins
  sorted by name). `provider` is still scalar; revisit if CDNs/BYOIP make multi-provider
  ownership common.
- **rezmoss reality:** the CC0 mirror does **not** republish the raw provider files —
  it normalizes every provider to a uniform `{ip_address, ip_type, service, region}`
  schema at `<provider>/<provider>_ips.json` (GCP is filed under `googlecloud/`). So
  `--source rezmoss` uses a single shared decoder (`ParseRezmoss`), while `--source
  direct` uses each plugin's native parser against the provider's own URL. The mirror
  carries no per-entry timestamp, so rezmoss-built records have `synced_at=0`; the
  build epoch is still stamped in MMDB metadata. Providers without a stable direct URL
  (Azure) fall back to rezmoss automatically.

## Licensing

The MMDB `DatabaseType` is `Cloud-Attribution` — **not** `GeoIP*` (reserved +
MaxMind trademark). Dependencies: `mmdbwriter` (Apache-2.0/MIT),
`maxminddb-golang` (ISC). The rezmoss mirror is CC0, but upstream provider terms
still apply to the data.
