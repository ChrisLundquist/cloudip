// Package feodo normalizes the abuse.ch Feodo Tracker IP blocklist (botnet C2
// servers for Emotet/Dridex/QakBot/etc.) into attribution entries.
//
// Feed: https://feodotracker.abuse.ch/downloads/ipblocklist.json — published
// under CC0 (https://feodotracker.abuse.ch/blocklist/), so it carries no
// redistribution restrictions. Entries are single IPs, recorded as /32.
package feodo

import (
	"encoding/json"
	"io"
	"iter"
	"net/netip"
	"strconv"
	"time"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func init() { attribution.RegisterReputation(Plugin{}) }

// Plugin implements attribution.Plugin for the Feodo Tracker blocklist.
type Plugin struct{}

func (Plugin) Name() string { return "feodo" }

// Refs is the offline/fixture path; DirectRefs is the live URL.
func (Plugin) Refs() []string { return []string{"feodo/ipblocklist.json"} }

// DirectURL is the canonical CC0 feed.
const DirectURL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

// DirectRefs returns the provider's own URL for --source direct.
func (Plugin) DirectRefs() []string { return []string{DirectURL} }

// entry mirrors the subset of ipblocklist.json we consume.
type entry struct {
	IPAddress  string `json:"ip_address"`
	Port       int    `json:"port"`
	Status     string `json:"status"`
	FirstSeen  string `json:"first_seen"`
	LastOnline string `json:"last_online"`
	Malware    string `json:"malware"`
}

// Parse normalizes the Feodo blocklist into /32 entries tagged "botnet_c2".
func (Plugin) Parse(ref string, r io.Reader) iter.Seq2[attribution.Entry, error] {
	return func(yield func(attribution.Entry, error) bool) {
		var doc []entry
		if err := json.NewDecoder(r).Decode(&doc); err != nil {
			yield(attribution.Entry{}, err)
			return
		}
		for _, e := range doc {
			addr, err := netip.ParseAddr(e.IPAddress)
			if err != nil {
				if !yield(attribution.Entry{}, err) {
					return
				}
				continue
			}
			ext := map[string]string{}
			if e.Malware != "" {
				ext["malware"] = e.Malware
			}
			if e.Status != "" {
				ext["status"] = e.Status // "online"/"offline": liveness of the C2
			}
			if e.Port != 0 {
				ext["port"] = strconv.Itoa(e.Port)
			}
			rec := attribution.Record{
				Provider:   "abuse.ch",
				Categories: []string{"botnet_c2", "malware"},
				Source:     ref,
				// synced_at tracks freshness: prefer last_online so a long-dead C2
				// isn't stamped as if it were just observed; fall back to first_seen.
				SyncedAt: feodoTime(e.LastOnline, e.FirstSeen),
				Ext:      ext,
			}
			if !yield(attribution.Entry{Network: hostPrefix(addr), Record: rec}, nil) {
				return
			}
		}
	}
}

// hostPrefix returns addr as a single-host prefix (/32 or /128).
func hostPrefix(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, a.BitLen()) }

// feodoTime returns the freshest parseable timestamp from the candidates. The
// feed uses "2006-01-02 15:04:05" for first_seen and a date-only "2006-01-02"
// for last_online.
func feodoTime(candidates ...string) time.Time {
	for _, s := range candidates {
		for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02"} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}
