package attribution

import (
	"context"
	"encoding/json"
	"io"
	"iter"
	"net/netip"
	"time"
)

// RezmossPlugin is implemented by plugins whose rezmoss mirror path differs from
// the default "<name>/<name>_ips.json" (e.g. GCP, mirrored as "googlecloud").
type RezmossPlugin interface {
	Plugin
	RezmossRefs() []string
}

// RezmossRefs returns the rezmoss-mirror file path(s) for a plugin: the plugin's
// own override if it provides one, otherwise the "<name>/<name>_ips.json"
// convention the mirror uses.
func RezmossRefs(p Plugin) []string {
	if rp, ok := p.(RezmossPlugin); ok {
		return rp.RezmossRefs()
	}
	n := p.Name()
	return []string{n + "/" + n + "_ips.json"}
}

// rezmossEntry is the uniform record the rezmoss CC0 mirror publishes for every
// provider: a flat array of {ip_address, ip_type, service, region}. This is a
// normalized reshaping of the upstream feeds, not the providers' native schemas
// (which the native plugins parse for --source direct).
type rezmossEntry struct {
	IPAddress string `json:"ip_address"`
	IPType    string `json:"ip_type"`
	Service   string `json:"service"`
	Region    string `json:"region"`
}

// ParseRezmoss returns a ParseFunc for the uniform rezmoss schema, tagging every
// entry with the given provider. The array is stream-decoded so large feeds
// don't have to be held in memory at once.
func ParseRezmoss(provider string) ParseFunc {
	return func(ref string, r io.Reader) iter.Seq2[Entry, error] {
		return func(yield func(Entry, error) bool) {
			dec := json.NewDecoder(r)
			// Consume the opening '['.
			if _, err := dec.Token(); err != nil {
				yield(Entry{}, err)
				return
			}
			for dec.More() {
				var re rezmossEntry
				if err := dec.Decode(&re); err != nil {
					// A decode (syntax) error is terminal: the json.Decoder cannot
					// resynchronize, so More() would stay true and re-yield forever.
					yield(Entry{}, err)
					return
				}
				pre, err := parseRezmossPrefix(re.IPAddress)
				if err != nil {
					if !yield(Entry{}, err) {
						return
					}
					continue
				}
				region := re.Region
				if region == "GLOBAL" {
					region = "" // rezmoss uses "GLOBAL" where the provider gives no region
				}
				service := re.Service
				if service == "" {
					service = re.IPType // degenerate feeds: keep something non-empty
				}
				ok := yield(Entry{
					Network: pre,
					Record: Record{
						Provider: provider,
						Region:   region,
						Services: []string{service},
						Source:   ref,
					},
				}, nil)
				if !ok {
					return
				}
			}
		}
	}
}

// RezmossAllRef is the rezmoss mirror's single unified file covering every
// provider it tracks (aws, azure, googlecloud, cloudflare, fastly, oracle,
// linode, digitalocean, vultr, github, zoom, and various bot networks).
const RezmossAllRef = "all_providers/all_providers.json"

// rezmossAllEntry is the schema of all_providers.json. Unlike the per-provider
// files it carries the provider name and a last_updated timestamp per record.
type rezmossAllEntry struct {
	CIDR        string `json:"cidr"`
	IPVersion   string `json:"ip_version"`
	Provider    string `json:"provider"`
	Service     string `json:"service"`
	Region      string `json:"region"`
	LastUpdated string `json:"last_updated"`
}

// ParseRezmossAll parses the unified all_providers.json. Each entry's provider
// comes from the record itself. If filter is non-empty, only records whose
// provider is a key in filter are emitted.
func ParseRezmossAll(filter map[string]bool) ParseFunc {
	return func(ref string, r io.Reader) iter.Seq2[Entry, error] {
		return func(yield func(Entry, error) bool) {
			dec := json.NewDecoder(r)
			if _, err := dec.Token(); err != nil { // opening '['
				yield(Entry{}, err)
				return
			}
			for dec.More() {
				var re rezmossAllEntry
				if err := dec.Decode(&re); err != nil {
					// Terminal: the decoder can't resync past a syntax error.
					yield(Entry{}, err)
					return
				}
				if len(filter) > 0 && !filter[re.Provider] {
					continue
				}
				pre, err := parseRezmossPrefix(re.CIDR)
				if err != nil {
					if !yield(Entry{}, err) {
						return
					}
					continue
				}
				region := re.Region
				if region == "GLOBAL" {
					region = ""
				}
				services := []string(nil)
				if re.Service != "" {
					services = []string{re.Service}
				}
				ok := yield(Entry{
					Network: pre,
					Record: Record{
						Provider: re.Provider,
						Region:   region,
						Services: services,
						Source:   ref,
						SyncedAt: parseRezmossTime(re.LastUpdated),
					},
				}, nil)
				if !ok {
					return
				}
			}
		}
	}
}

// CollectRezmossAll yields every entry in the unified rezmoss file, optionally
// filtered to the named providers. src is typically NewRezmossSource(); pass a
// FileSource to build offline from a downloaded copy.
func CollectRezmossAll(ctx context.Context, src Source, providers []string) iter.Seq2[Entry, error] {
	filter := map[string]bool{}
	for _, p := range providers {
		filter[p] = true
	}
	feed := Feed{Ref: RezmossAllRef, Source: src, Parse: ParseRezmossAll(filter)}
	return func(yield func(Entry, error) bool) {
		collectFeed(ctx, "rezmoss-all", feed, yield)
	}
}

// parseRezmossPrefix parses a rezmoss network field. The mirror is overwhelmingly
// CIDRs, but the feeds occasionally emit a bare host IP with no '/' (e.g. a
// single announced /32 rendered as "5.134.119.103"). Treat that as a single-host
// prefix (/32 for v4, /128 for v6) rather than failing the whole build.
func parseRezmossPrefix(s string) (netip.Prefix, error) {
	pre, err := netip.ParsePrefix(s)
	if err == nil {
		return pre, nil
	}
	addr, aerr := netip.ParseAddr(s)
	if aerr != nil {
		return netip.Prefix{}, err // report the original ParsePrefix error
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// parseRezmossTime parses all_providers.json's "2006-01-02 15:04:05" timestamp,
// returning the zero time on anything unparseable.
func parseRezmossTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}
