// Package gcp normalizes Google Cloud's cloud.json into attribution entries.
// Each prefix carries a service ("Google Cloud") and a scope, which is the
// closest thing GCP publishes to a region (e.g. "us-central1", "global").
package gcp

import (
	"encoding/json"
	"io"
	"iter"
	"net/netip"
	"strings"
	"time"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func init() { attribution.Register(Plugin{}) }

// Plugin implements attribution.Plugin for GCP.
type Plugin struct{}

func (Plugin) Name() string { return "gcp" }

// Refs returns the rezmoss-relative path to cloud.json.
func (Plugin) Refs() []string { return []string{"gcp/cloud.json"} }

// DirectURL is the canonical GCP feed.
const DirectURL = "https://www.gstatic.com/ipranges/cloud.json"

// DirectRefs returns the provider's own URL for --source direct.
func (Plugin) DirectRefs() []string { return []string{DirectURL} }

// RezmossRefs overrides the default "<name>/<name>_ips.json": the rezmoss mirror
// files GCP under "googlecloud", not "gcp".
func (Plugin) RezmossRefs() []string { return []string{"googlecloud/googlecloud_ips.json"} }

// cloudJSON mirrors the subset of cloud.json we consume.
type cloudJSON struct {
	SyncToken    string `json:"syncToken"`
	CreationTime string `json:"creationTime"`
	Prefixes     []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
		Service    string `json:"service"`
		Scope      string `json:"scope"`
	} `json:"prefixes"`
}

// Parse normalizes cloud.json bytes into entries.
func (Plugin) Parse(ref string, r io.Reader) iter.Seq2[attribution.Entry, error] {
	return func(yield func(attribution.Entry, error) bool) {
		var doc cloudJSON
		if err := json.NewDecoder(r).Decode(&doc); err != nil {
			yield(attribution.Entry{}, err)
			return
		}
		syncedAt := parseGCPTime(doc.CreationTime)

		for _, p := range doc.Prefixes {
			cidr := p.IPv4Prefix
			if cidr == "" {
				cidr = p.IPv6Prefix
			}
			if cidr == "" {
				continue // neither field set: skip
			}
			pre, err := netip.ParsePrefix(cidr)
			if err != nil {
				if !yield(attribution.Entry{}, err) {
					return
				}
				continue
			}
			service := p.Service
			if service == "" {
				service = "Google Cloud"
			}
			region := p.Scope // scope is GCP's region analogue
			if strings.EqualFold(region, "global") {
				region = "" // align with the rezmoss path, which drops "GLOBAL"
			}
			ok := yield(attribution.Entry{
				Network: pre,
				Record: attribution.Record{
					Provider: "gcp",
					Region:   region,
					Services: []string{service},
					Source:   ref,
					SyncedAt: syncedAt,
				},
			}, nil)
			if !ok {
				return
			}
		}
	}
}

func parseGCPTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// cloud.json uses RFC3339 with a numeric offset, e.g. 2024-06-07T20:53:14.000000.
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000000"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
