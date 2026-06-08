// Package tor normalizes the Tor Project's bulk exit-node list into attribution
// entries (anonymizer detection).
//
// Feed: https://check.torproject.org/torbulkexitlist — the Tor Project publishes
// it openly. It is a plain list of exit IPs, one per line; recorded as /32.
package tor

import (
	"bufio"
	"io"
	"iter"
	"net/netip"
	"strings"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func init() { attribution.RegisterReputation(Plugin{}) }

// Plugin implements attribution.Plugin for the Tor exit list.
type Plugin struct{}

func (Plugin) Name() string { return "tor" }

// Refs is the offline/fixture path; DirectRefs is the live URL.
func (Plugin) Refs() []string { return []string{"tor/exit-list.txt"} }

// DirectURL is the canonical Tor bulk exit list.
const DirectURL = "https://check.torproject.org/torbulkexitlist"

// DirectRefs returns the provider's own URL for --source direct.
func (Plugin) DirectRefs() []string { return []string{DirectURL} }

// Parse normalizes one-IP-per-line exit lists into /32 entries tagged
// "tor_exit"/"anonymizer".
func (Plugin) Parse(ref string, r io.Reader) iter.Seq2[attribution.Entry, error] {
	return func(yield func(attribution.Entry, error) bool) {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			addr, err := netip.ParseAddr(line)
			if err != nil {
				if !yield(attribution.Entry{}, err) {
					return
				}
				continue
			}
			rec := attribution.Record{
				Provider:   "tor",
				Categories: []string{"tor_exit", "anonymizer"},
				Source:     ref,
			}
			if !yield(attribution.Entry{Network: netip.PrefixFrom(addr, addr.BitLen()), Record: rec}, nil) {
				return
			}
		}
		if err := sc.Err(); err != nil {
			yield(attribution.Entry{}, err)
		}
	}
}
