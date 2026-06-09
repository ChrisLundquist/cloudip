// Package attribution provides GeoIP-style attribution of IP networks to cloud
// providers. Per-provider plugins normalize published IP ranges into a single
// MMDB (DatabaseType "Cloud-Attribution"); a thin reader library is wrapped by
// gRPC / HTTP / CLI, and the same MMDB is consumed directly by nginx via
// ngx_http_geoip2_module.
//
// The package is split into a builder (entries -> .mmdb, see build.go) and a
// reader (reader.go). They share only the .mmdb file and the record schema.
package attribution

import (
	"context"
	"io"
	"iter"
	"net/netip"
	"time"
)

// Record is the normalized, provider-agnostic attribution payload for one
// network. It is the "stable core" that is uniformly queryable across every
// provider, plus Ext: a provider-namespaced map for specialization.
type Record struct {
	// Provider is the plugin that produced this record: "aws", "azure", "gcp".
	Provider string
	// Region is the provider region, or "" if the provider gives none (e.g. GCP).
	Region string
	// Services accumulates on overlapping prefixes: AWS lists the same CIDR once
	// per owning service, so this is an array, not a scalar (see mergeServices).
	Services []string
	// Categories holds reputation/intelligence tags for an IP — "botnet_c2",
	// "tor_exit", "drop", etc. Cloud plugins leave it empty; reputation plugins
	// set it. Unlike Services, categories union across providers on overlap, so a
	// single record can say "AWS us-east-1, and also a known Tor exit".
	Categories []string
	// IPv6 reports whether the network is an IPv6 network. It is derived at build
	// time from the prefix, not supplied by plugins.
	IPv6 bool
	// Source is provenance: the ref the record was parsed from, e.g. "ip-ranges.json".
	Source string
	// SyncedAt is the unix epoch of the feed the record came from.
	SyncedAt time.Time
	// Ext is the specialization escape hatch: provider-specific keys that do not
	// belong in the stable core (AWS network_border_group, Azure systemService, ...).
	// Values are stored in the MMDB as strings so nginx can reach them.
	Ext map[string]string
	// Network is the matched network, set by the reader on Lookup. It is NOT
	// stored in the MMDB (a stored network would rot when the tree splits ranges,
	// and would defeat record deduplication); plugins leave it zero. It is the
	// matched TREE NODE, which can be narrower than the CIDR a feed published:
	// inserting a /32 inside a /20 fragments the /20 into smaller nodes sharing
	// one record. Always a range that contains the queried IP and resolves to
	// exactly this record — the same semantics as MaxMind's `network` field.
	Network netip.Prefix
}

// Entry is one network and its normalized record, as yielded by a plugin.
type Entry struct {
	Network netip.Prefix
	Record  Record
}

// Source abstracts where raw bytes come from: a rezmoss path, a provider URL,
// or a local cache file. It lets tests inject fixtures and lets ops pin to a
// CC0 rezmoss mirror instead of hitting provider URLs directly.
type Source interface {
	// Open resolves a ref (its meaning is Source-specific) to a byte stream.
	Open(ctx context.Context, ref string) (io.ReadCloser, error)
}

// Plugin is implemented once per cloud provider. Its only job: declare which
// refs it needs and normalize already-fetched bytes into entries. It knows
// nothing about MMDB, gRPC, or merging. Splitting Refs/Parse from fetching
// means the builder owns IO (retries, caching, rezmoss-vs-direct) and Parse
// stays a pure function over bytes — trivial to unit-test against fixtures.
type Plugin interface {
	// Name is the provider identifier: "aws", "azure", "gcp".
	Name() string
	// Refs returns the source references this plugin needs (URLs or rezmoss paths).
	Refs() []string
	// Parse normalizes already-fetched bytes for one ref into entries.
	Parse(ref string, r io.Reader) iter.Seq2[Entry, error]
}

// DirectPlugin is an optional interface a Plugin implements when it can hit the
// provider's own URLs (--source direct) instead of the rezmoss CC0 mirror. The
// returned URLs correspond positionally to Refs(); the builder passes them to
// the Source and on to Parse as the provenance ref.
type DirectPlugin interface {
	Plugin
	DirectRefs() []string
}

// RefsFor returns the refs to fetch for a plugin: the provider's own URLs when
// direct is true and the plugin supports it, otherwise its rezmoss refs.
func RefsFor(p Plugin, direct bool) []string {
	if direct {
		if dp, ok := p.(DirectPlugin); ok {
			return dp.DirectRefs()
		}
	}
	return p.Refs()
}

// registry holds plugins that self-register via init().
var registry = map[string]Plugin{}

// Register adds a plugin to the global registry. Plugins call this from init().
// A later registration for the same Name replaces the earlier one.
func Register(p Plugin) { registry[p.Name()] = p }

// Plugins returns a copy of the registry so callers cannot mutate it.
func Plugins() map[string]Plugin {
	out := make(map[string]Plugin, len(registry))
	for k, v := range registry {
		out[k] = v
	}
	return out
}

// Lookup returns the plugin registered under name, if any.
func Lookup(name string) (Plugin, bool) {
	p, ok := registry[name]
	return p, ok
}

// reputationRegistry holds reputation/intelligence plugins (botnet C2, Tor exits,
// Spamhaus DROP, ...). They are kept separate from cloud-provider plugins so a
// cloud build and a reputation build select independently; both produce a
// Cloud-Attribution MMDB, the reputation one carrying Categories.
var reputationRegistry = map[string]Plugin{}

// RegisterReputation adds a reputation plugin. Plugins call this from init().
func RegisterReputation(p Plugin) { reputationRegistry[p.Name()] = p }

// ReputationPlugins returns a copy of the reputation registry.
func ReputationPlugins() map[string]Plugin {
	out := make(map[string]Plugin, len(reputationRegistry))
	for k, v := range reputationRegistry {
		out[k] = v
	}
	return out
}

// asnRegistry holds IP->ASN plugins (BGP-derived origin-AS tables). Like
// reputation, they are a separate registry so an ASN build selects
// independently of cloud builds; the records carry asn/as_org in Ext.
var asnRegistry = map[string]Plugin{}

// RegisterASN adds an ASN plugin. Plugins call this from init().
func RegisterASN(p Plugin) { asnRegistry[p.Name()] = p }

// ASNPlugins returns a copy of the ASN registry.
func ASNPlugins() map[string]Plugin {
	out := make(map[string]Plugin, len(asnRegistry))
	for k, v := range asnRegistry {
		out[k] = v
	}
	return out
}
