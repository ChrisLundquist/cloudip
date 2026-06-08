package azure

import (
	"os"
	"strings"
	"testing"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func TestParseBadJSON(t *testing.T) {
	var sawErr bool
	for _, err := range (Plugin{}).Parse("x", strings.NewReader("{not json")) {
		if err != nil {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatal("expected a parse error for malformed JSON")
	}
}

func TestParse(t *testing.T) {
	f, err := os.Open("testdata/ServiceTags_Public.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	byCIDR := map[string]attribution.Record{}
	for e, err := range (Plugin{}).Parse("azure/ServiceTags_Public.json", f) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		byCIDR[e.Network.String()] = e.Record
	}

	if got, want := len(byCIDR), 3; got != want {
		t.Fatalf("got %d networks, want %d", got, want)
	}

	storage := byCIDR["13.66.176.0/20"]
	if storage.Provider != "azure" {
		t.Errorf("provider = %q", storage.Provider)
	}
	if storage.Region != "westus" {
		t.Errorf("region = %q, want westus", storage.Region)
	}
	if storage.Services[0] != "AzureStorage" {
		t.Errorf("service = %v, want AzureStorage", storage.Services)
	}
	if storage.Ext["system_service"] != "AzureStorage" || storage.Ext["platform"] != "Azure" {
		t.Errorf("ext = %v", storage.Ext)
	}

	// When systemService is blank, the tag name becomes the service.
	cloud := byCIDR["20.42.0.0/16"]
	if cloud.Services[0] != "AzureCloud.eastus" {
		t.Errorf("fallback service = %v, want AzureCloud.eastus", cloud.Services)
	}
}
