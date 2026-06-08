// Package azure normalizes Azure's ServiceTags_Public JSON (the published
// "service tags" feed) into attribution entries. Each tag carries a system
// service, a platform, an optional region, and a list of address prefixes.
package azure

import (
	"encoding/json"
	"io"
	"iter"
	"net/netip"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func init() { attribution.Register(Plugin{}) }

// Plugin implements attribution.Plugin for Azure.
type Plugin struct{}

func (Plugin) Name() string { return "azure" }

// Refs returns the rezmoss-relative path to the service tags file.
func (Plugin) Refs() []string { return []string{"azure/ServiceTags_Public.json"} }

// DirectURL is the stable Azure download endpoint for the public service tags.
// (Microsoft publishes a dated file behind a download page; rezmoss mirrors a
// canonical name, which is why rezmoss is the default source.)
const DirectURL = "https://www.microsoft.com/download/details.aspx?id=56519"

// serviceTags mirrors the subset of the service-tags file we consume.
type serviceTags struct {
	ChangeNumber int    `json:"changeNumber"`
	Cloud        string `json:"cloud"`
	Values       []struct {
		Name       string `json:"name"`
		Properties struct {
			Region          string   `json:"region"`
			Platform        string   `json:"platform"`
			SystemService   string   `json:"systemService"`
			AddressPrefixes []string `json:"addressPrefixes"`
		} `json:"properties"`
	} `json:"values"`
}

// Parse normalizes service-tags bytes into entries.
func (Plugin) Parse(ref string, r io.Reader) iter.Seq2[attribution.Entry, error] {
	return func(yield func(attribution.Entry, error) bool) {
		var doc serviceTags
		if err := json.NewDecoder(r).Decode(&doc); err != nil {
			yield(attribution.Entry{}, err)
			return
		}

		for _, tag := range doc.Values {
			service := tag.Properties.SystemService
			if service == "" {
				service = tag.Name // e.g. "AzureCloud.westus" when no systemService
			}
			ext := map[string]string{}
			if tag.Properties.SystemService != "" {
				ext["system_service"] = tag.Properties.SystemService
			}
			if tag.Properties.Platform != "" {
				ext["platform"] = tag.Properties.Platform
			}

			for _, cidr := range tag.Properties.AddressPrefixes {
				pre, err := netip.ParsePrefix(cidr)
				if err != nil {
					if !yield(attribution.Entry{}, err) {
						return
					}
					continue
				}
				ok := yield(attribution.Entry{
					Network: pre,
					Record: attribution.Record{
						Provider: "azure",
						Region:   tag.Properties.Region,
						Services: []string{service},
						Source:   ref,
						Ext:      ext,
					},
				}, nil)
				if !ok {
					return
				}
			}
		}
	}
}
