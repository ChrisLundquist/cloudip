// Package spamhaus normalizes the Spamhaus DROP list (Don't Route Or Peer —
// hijacked and cybercriminal-controlled netblocks) into attribution entries.
//
// Feed: https://www.spamhaus.org/drop/drop.txt. DROP is free to use, including
// commercially, and redistributable provided Spamhaus is named as the source and
// the copyright/timestamp header is retained — see https://www.spamhaus.org/drop/terms/.
// We honor that by tagging every record provider="spamhaus", source=drop.txt and
// preserving the SBL reference in ext. (eDROP was merged into DROP in 2024.)
package spamhaus

import (
	"bufio"
	"io"
	"iter"
	"net/netip"
	"strings"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func init() { attribution.RegisterReputation(Plugin{}) }

// Plugin implements attribution.Plugin for the Spamhaus DROP list.
type Plugin struct{}

func (Plugin) Name() string { return "spamhaus" }

// Refs is the offline/fixture path; DirectRefs is the live URL.
func (Plugin) Refs() []string { return []string{"spamhaus/drop.txt"} }

// DirectURL is the canonical DROP feed.
const DirectURL = "https://www.spamhaus.org/drop/drop.txt"

// DirectRefs returns the provider's own URL for --source direct.
func (Plugin) DirectRefs() []string { return []string{DirectURL} }

// Parse normalizes drop.txt lines ("CIDR ; SBLnnnnn"; ";"-prefixed comments are
// skipped) into entries tagged "drop"/"hijacked".
func (Plugin) Parse(ref string, r io.Reader) iter.Seq2[attribution.Entry, error] {
	return func(yield func(attribution.Entry, error) bool) {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, ";") {
				continue // blank or copyright/metadata comment
			}
			cidr, sbl := splitDROP(line)
			pre, err := netip.ParsePrefix(cidr)
			if err != nil {
				if !yield(attribution.Entry{}, err) {
					return
				}
				continue
			}
			ext := map[string]string{}
			if sbl != "" {
				ext["sbl"] = sbl
			}
			rec := attribution.Record{
				Provider:   "spamhaus",
				Categories: []string{"drop", "hijacked"},
				Source:     ref,
				Ext:        ext,
			}
			if !yield(attribution.Entry{Network: pre, Record: rec}, nil) {
				return
			}
		}
		if err := sc.Err(); err != nil {
			yield(attribution.Entry{}, err)
		}
	}
}

// splitDROP parses "1.2.3.0/24 ; SBL12345" into its CIDR and SBL reference.
func splitDROP(line string) (cidr, sbl string) {
	if i := strings.IndexByte(line, ';'); i >= 0 {
		cidr = strings.TrimSpace(line[:i])
		sbl = strings.TrimSpace(line[i+1:])
	} else {
		cidr = strings.TrimSpace(line)
	}
	return cidr, sbl
}
