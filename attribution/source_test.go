package attribution

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPSourceRetriesTransient(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Fail twice with a 503, then succeed.
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("payload"))
	}))
	defer srv.Close()

	src := &HTTPSource{Attempts: 3, Backoff: time.Millisecond}
	rc, err := src.Open(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	if string(b) != "payload" {
		t.Errorf("body = %q", b)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("server called %d times, want 3 (2 retries)", got)
	}
}

func TestHTTPSourceFailsFastOn404(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	src := &HTTPSource{Attempts: 4, Backoff: time.Millisecond}
	if _, err := src.Open(context.Background(), srv.URL); err == nil {
		t.Fatal("expected error on 404")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("404 retried %d times, want 1 (fail fast)", got)
	}
}

func TestHTTPSourceExhaustsAttempts(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	src := &HTTPSource{Attempts: 3, Backoff: time.Millisecond}
	if _, err := src.Open(context.Background(), srv.URL); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("server called %d times, want 3 attempts", got)
	}
}

func TestFileSourceConfinement(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.json"), []byte(`[]`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A secret living outside the source dir.
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("top secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := FileSource{Dir: dir}

	// In-dir ref works.
	rc, err := src.Open(context.Background(), "ok.json")
	if err != nil {
		t.Fatalf("in-dir open failed: %v", err)
	}
	rc.Close()

	// Traversal refs must be rejected, not silently read.
	for _, ref := range []string{"../secret", "../../etc/hostname", "a/../../secret"} {
		if rc, err := src.Open(context.Background(), ref); err == nil {
			b, _ := io.ReadAll(rc)
			rc.Close()
			t.Errorf("ref %q escaped source dir and read %q", ref, b)
		}
	}

	// Absolute ref is confined under Dir (so it can't read /etc/hostname).
	if rc, err := src.Open(context.Background(), "/etc/hostname"); err == nil {
		rc.Close()
		t.Error("absolute ref was not confined to source dir")
	}
}
