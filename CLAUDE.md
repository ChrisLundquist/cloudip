# CLAUDE.md

Guidance for working in this repo. See `README.md` for user-facing docs and
`prompt.md` for the original design sketch.

## What this is

`cloudip` does GeoIP-style attribution of IP networks to cloud providers. Plugins
normalize published IP ranges into one MMDB (`DatabaseType: Cloud-Attribution`);
a thin reader is wrapped by gRPC / HTTP / CLI, and the same MMDB is read directly
by nginx via the stock `ngx_http_geoip2_module`. Module path:
`github.com/ChrisLundquist/cloudip`. Go 1.26+ (uses `iter.Seq2`).

## Layout

- `attribution/` — the core library, no CLI/server deps.
  - `attribution.go` — `Record`, `Entry`, `Source`, `Plugin`, registry, optional
    `DirectPlugin`/`RezmossPlugin` interfaces.
  - `build.go` — `Build` (entries → MMDB) + the **service-union merge inserter**
    (`mergeRecords`). Returns `BuildStats{Inserted,Skipped}`; structurally-rejected
    networks (aliased 6to4/Teredo) are skipped, not fatal.
  - `storage.go` — `Record` ↔ `mmdbtype` and the on-disk `storedRecord` (decode).
  - `reader.go` — `DB`, `Open`/`OpenBytes`, `Lookup`, `Networks` walk.
  - `pipeline.go` — `Feed` (source+ref+parser), `Collect`, and the resolvers
    (`Rezmoss`/`Direct`/`Fixture`). This is the seam between IO and parsing.
  - `rezmoss.go` — uniform rezmoss decoders: `ParseRezmoss` (per-provider file)
    and `ParseRezmossAll` + `CollectRezmossAll` (the unified all_providers.json).
  - `export.go` (CSV), `verify.go` (tree walk + counts), `sync.go` (`BuildFile`:
    atomic temp→verify→drop-guard→rename).
- `plugins/{aws,azure,gcp}/` — native parsers, self-register via `init()`, each
  with a `testdata/` fixture in the provider's OWN schema. `plugins/all` blank-
  imports them.
- `server/` — `Service` (atomic DB swap for reload) + `grpc.go` + `http.go`.
- `cmd/cloudattr/` — CLI: `build` / `lookup` / `export` / `verify` / `serve`.
- `proto/` — `.proto` + generated `cloudattrpb`. Regenerate with `make proto`.
- `internal/nginxtest/` — end-to-end nginx + geoip2 + PROXY-protocol test.
- `deploy/nginx-geoip2.conf` — example nginx config.

## Conventions / gotchas

- **`DatabaseType` must never start with `GeoIP`** (reserved + trademark). It is
  `Cloud-Attribution`.
- **`services` is an array and unions on overlapping prefixes.** AWS lists a CIDR
  once per service; never make it a scalar. The merge logic lives in
  `mergeRecords`/`unionSlices` and is covered by `TestBuildMergesServices`.
- **`ext` is stored as `map<string,string>`** so nginx can read every leaf.
- **Two data realities for rezmoss:** the mirror does NOT republish raw provider
  files — it normalizes to `{ip_address,ip_type,service,region}` per provider at
  `<provider>/<provider>_ips.json` (GCP under `googlecloud/`), and to
  `{cidr,ip_version,provider,service,region,last_updated}` in
  `all_providers/all_providers.json`. Native plugin schemas (in `testdata/`) are
  only for `--source direct`. See the `rezmoss-mirror-layout` memory.
- **Never commit `.mmdb`/`.csv`** — they're build artifacts and git-ignored.
- **The reader mmaps the file; publish only via atomic rename.** `BuildFile`
  (build + CSV export) writes a temp file, fsyncs, and renames. Never overwrite a
  live `.mmdb` in place — it corrupts the running reader's mmap. `Service.Reload`
  uses `OpenValidated` and only swaps on success, so a corrupt/partial replacement
  is rejected and the old DB keeps serving. The swapped-out handle is closed after
  a `closeGrace` delay (never synchronously) to avoid munmap-under-lookup.
- **Build epoch** is stamped into MMDB metadata so `/version` and the warehouse
  partition agree; rezmoss-built records may have `synced_at=0` (no per-entry
  timestamp in the per-provider files; the all file does carry one).

## Build / test

```sh
export PATH=$PATH:/opt/homebrew/bin   # Go is brew-installed here
go build ./...
go test ./...                          # unit + server + nginx integration
go vet ./... && gofmt -l <files>       # keep both clean before committing
make cli                               # -> bin/cloudattr
make proto                             # regenerate gRPC stubs (needs protoc + plugins)
```

The nginx test self-skips unless `nginx`, the `ngx_http_geoip2_module` (built in
or via `CLOUDIP_GEOIP2_MODULE=/path/ngx_http_geoip2_module.so`), and a curl with
`--haproxy-clientip` are all present. When editing it, remember nginx forks a
worker that inherits stdout — stop the whole process group (it runs with
`Setpgid`) or `cmd.Wait()` will hang.

## Adding a provider plugin

Implement `attribution.Plugin` (`Name`/`Refs`/pure `Parse`), register in `init()`,
add a `testdata/` fixture + table test. Optionally add `DirectRefs()` (direct
mode) and `RezmossRefs()` (if the mirror path isn't `<name>/<name>_ips.json`).
Keep `Parse` a pure function over bytes — the builder owns all IO.
