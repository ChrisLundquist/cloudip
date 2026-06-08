package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ChrisLundquist/cloudip/attribution"
)

// jsonRecord is the HTTP JSON shape of a record. synced_at is a unix epoch so
// the wire form matches the MMDB and gRPC representations.
type jsonRecord struct {
	Provider   string            `json:"provider"`
	Region     string            `json:"region"`
	Services   []string          `json:"services"`
	Categories []string          `json:"categories,omitempty"`
	IPv6       bool              `json:"ipv6"`
	Source     string            `json:"source"`
	SyncedAt   int64             `json:"synced_at"`
	Ext        map[string]string `json:"ext,omitempty"`
}

func toJSON(r attribution.Record) jsonRecord {
	var synced int64
	if !r.SyncedAt.IsZero() {
		synced = r.SyncedAt.Unix()
	}
	svcs := r.Services
	if svcs == nil {
		svcs = []string{}
	}
	return jsonRecord{
		Provider: r.Provider, Region: r.Region, Services: svcs, Categories: r.Categories,
		IPv6: r.IPv6, Source: r.Source, SyncedAt: synced, Ext: r.Ext,
	}
}

// batchResult is one element of the batch-lookup response.
type batchResult struct {
	IP     string      `json:"ip"`
	Found  bool        `json:"found"`
	Record *jsonRecord `json:"record,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// NewHTTPHandler builds the HTTP mux for the service.
//
//	GET /v1/lookup/{ip}        -> 200 {record} | 404
//	GET /v1/lookup?ip=&ip=     -> 200 [{ip,found,record}, ...]  (batch)
//	GET /healthz  /metrics  /version
func NewHTTPHandler(svc *Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/lookup/{ip}", svc.handleLookupOne)
	mux.HandleFunc("GET /v1/lookup", svc.handleLookupBatch)
	mux.HandleFunc("GET /healthz", svc.handleHealthz)
	mux.HandleFunc("GET /version", svc.handleVersion)
	mux.HandleFunc("GET /metrics", svc.handleMetrics)
	return mux
}

func (s *Service) handleLookupOne(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	rec, found, err := s.Lookup(ip)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"ip": ip, "error": "not attributed"})
		return
	}
	writeJSON(w, http.StatusOK, toJSON(rec))
}

// maxBatch bounds how many IPs one batch request may carry, so a pathological
// query can't run unbounded work or exceed the server's WriteTimeout mid-response.
const maxBatch = 1024

func (s *Service) handleLookupBatch(w http.ResponseWriter, r *http.Request) {
	ips := r.URL.Query()["ip"]
	if len(ips) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no ip query parameter"})
		return
	}
	if len(ips) > maxBatch {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("too many ips: %d (max %d)", len(ips), maxBatch),
		})
		return
	}
	out := make([]batchResult, 0, len(ips))
	for _, ip := range ips {
		rec, found, err := s.Lookup(ip)
		br := batchResult{IP: ip, Found: found && err == nil}
		switch {
		case err != nil:
			br.Error = err.Error()
		case found:
			jr := toJSON(rec)
			br.Record = &jr
		}
		out = append(out, br)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	if s.DB() == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "no database"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Service) handleVersion(w http.ResponseWriter, _ *http.Request) {
	md := s.DB().Metadata()
	writeJSON(w, http.StatusOK, map[string]any{
		"build_epoch":   s.DB().BuildTime().Unix(),
		"build_time":    s.DB().BuildTime().UTC().Format(time.RFC3339),
		"database_type": md.DatabaseType,
		"node_count":    md.NodeCount,
		"record_size":   md.RecordSize,
	})
}

// handleMetrics emits Prometheus text-format counters without pulling in a
// client library.
func (s *Service) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	st := s.Stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE cloudattr_lookups_total counter\ncloudattr_lookups_total %d\n", st.Lookups)
	fmt.Fprintf(w, "# TYPE cloudattr_hits_total counter\ncloudattr_hits_total %d\n", st.Hits)
	fmt.Fprintf(w, "# TYPE cloudattr_errors_total counter\ncloudattr_errors_total %d\n", st.Errors)
	fmt.Fprintf(w, "# TYPE cloudattr_build_epoch gauge\ncloudattr_build_epoch %d\n", s.DB().BuildTime().Unix())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
