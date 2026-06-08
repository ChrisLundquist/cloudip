// Package aws normalizes Amazon's published ip-ranges.json into attribution
// entries. AWS lists a CIDR once per owning service, so the same prefix can
// appear several times; the builder's merge inserter unions the services.
package aws

import (
	"encoding/json"
	"io"
	"iter"
	"net/netip"
	"time"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func init() { attribution.Register(Plugin{}) }

// Plugin implements attribution.Plugin for AWS.
type Plugin struct{}

func (Plugin) Name() string { return "aws" }

// Refs returns the rezmoss-relative path to ip-ranges.json. In --source direct
// mode the builder substitutes the canonical AWS URL (see DirectRefs).
func (Plugin) Refs() []string { return []string{"aws/ip-ranges.json"} }

// DirectURL is the canonical provider feed, used by --source direct.
const DirectURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

// DirectRefs returns the provider's own URL for --source direct.
func (Plugin) DirectRefs() []string { return []string{DirectURL} }

// ipRanges mirrors the subset of ip-ranges.json we consume.
type ipRanges struct {
	SyncToken  string `json:"syncToken"`
	CreateDate string `json:"createDate"`
	Prefixes   []struct {
		IPPrefix           string `json:"ip_prefix"`
		Region             string `json:"region"`
		Service            string `json:"service"`
		NetworkBorderGroup string `json:"network_border_group"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		IPv6Prefix         string `json:"ipv6_prefix"`
		Region             string `json:"region"`
		Service            string `json:"service"`
		NetworkBorderGroup string `json:"network_border_group"`
	} `json:"ipv6_prefixes"`
}

// Parse normalizes ip-ranges.json bytes into entries. It is a pure function of
// its input: no IO, trivially testable against a checked-in fixture.
func (Plugin) Parse(ref string, r io.Reader) iter.Seq2[attribution.Entry, error] {
	return func(yield func(attribution.Entry, error) bool) {
		var doc ipRanges
		if err := json.NewDecoder(r).Decode(&doc); err != nil {
			yield(attribution.Entry{}, err)
			return
		}

		// AWS stamps the feed time as createDate (e.g. "2024-06-10-12-00-00").
		syncedAt := parseAWSDate(doc.CreateDate)

		emit := func(cidr, region, service, nbg string) bool {
			pre, err := netip.ParsePrefix(cidr)
			if err != nil {
				return yield(attribution.Entry{}, err)
			}
			ext := map[string]string{}
			if nbg != "" {
				ext["network_border_group"] = nbg
			}
			return yield(attribution.Entry{
				Network: pre,
				Record: attribution.Record{
					Provider: "aws",
					Region:   region,
					Services: []string{service},
					Source:   ref,
					SyncedAt: syncedAt,
					Ext:      ext,
				},
			}, nil)
		}

		for _, p := range doc.Prefixes {
			if !emit(p.IPPrefix, p.Region, p.Service, p.NetworkBorderGroup) {
				return
			}
		}
		for _, p := range doc.IPv6Prefixes {
			if !emit(p.IPv6Prefix, p.Region, p.Service, p.NetworkBorderGroup) {
				return
			}
		}
	}
}

// parseAWSDate parses AWS's "2006-01-02-15-04-05" createDate. A blank or
// unparseable value yields the zero time (recorded as synced_at=0).
func parseAWSDate(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02-15-04-05", s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
