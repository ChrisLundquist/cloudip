package server

import (
	"bytes"
	"encoding/json"
	"iter"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/ChrisLundquist/cloudip/attribution"
)

// buildTestDB writes a tiny MMDB to a temp file and returns its path.
func buildTestDB(t *testing.T) string {
	t.Helper()
	es := []attribution.Entry{
		{Network: netPrefix(t, "52.94.0.0/22"), Record: attribution.Record{Provider: "aws", Region: "us-east-1", Services: []string{"EC2", "S3"}}},
	}
	var buf bytes.Buffer
	if _, err := attribution.Build(seq(es), &buf, attribution.BuildOptions{BuildEpoch: 1718000000}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cloud.mmdb")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHTTPLookup(t *testing.T) {
	svc, err := NewService(buildTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	h := NewHTTPHandler(svc)

	// single hit
	rec := do(t, h, "/v1/lookup/52.94.0.1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var jr jsonRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &jr); err != nil {
		t.Fatal(err)
	}
	if jr.Provider != "aws" || len(jr.Services) != 2 {
		t.Errorf("record = %+v", jr)
	}

	// single miss -> 404
	if got := do(t, h, "/v1/lookup/203.0.113.1").Code; got != http.StatusNotFound {
		t.Errorf("miss status = %d, want 404", got)
	}

	// bad ip -> 400
	if got := do(t, h, "/v1/lookup/not-an-ip").Code; got != http.StatusBadRequest {
		t.Errorf("bad ip status = %d, want 400", got)
	}

	// batch: hit, miss, and a malformed IP that must carry an error
	batch := do(t, h, "/v1/lookup?ip=52.94.0.1&ip=203.0.113.1&ip=not-an-ip")
	var results []batchResult
	if err := json.Unmarshal(batch.Body.Bytes(), &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("batch len = %d, want 3", len(results))
	}
	if !results[0].Found || results[0].Error != "" {
		t.Errorf("hit = %+v", results[0])
	}
	if results[1].Found || results[1].Error != "" {
		t.Errorf("miss = %+v", results[1])
	}
	if results[2].Found || results[2].Error == "" {
		t.Errorf("malformed ip should carry error: %+v", results[2])
	}

	// health/version/metrics
	if do(t, h, "/healthz").Code != http.StatusOK {
		t.Error("healthz not ok")
	}
	ver := do(t, h, "/version")
	if !bytes.Contains(ver.Body.Bytes(), []byte("Cloud-Attribution")) {
		t.Errorf("version body = %s", ver.Body.String())
	}
	if !bytes.Contains(do(t, h, "/metrics").Body.Bytes(), []byte("cloudattr_lookups_total")) {
		t.Error("metrics missing counter")
	}
}

func netPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func seq(es []attribution.Entry) iter.Seq2[attribution.Entry, error] {
	return func(yield func(attribution.Entry, error) bool) {
		for _, e := range es {
			if !yield(e, nil) {
				return
			}
		}
	}
}

func do(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
