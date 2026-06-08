// Package server wraps the attribution reader with gRPC and HTTP frontends. A
// single Service holds the open database behind an atomic pointer so the file
// can be hot-swapped (SIGHUP / auto-reload) without dropping in-flight lookups.
package server

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ChrisLundquist/cloudip/attribution"
)

// closeGrace is how long a replaced database handle is kept mapped after a
// reload before its mmap is released. It must comfortably exceed the longest
// possible single Lookup (which is microseconds) so a goroutine that loaded the
// old handle just before the swap can never read unmapped memory.
const closeGrace = 30 * time.Second

// Service is the shared lookup core behind both the gRPC and HTTP servers.
type Service struct {
	path string
	db   atomic.Pointer[attribution.DB]

	lookups atomic.Int64
	hits    atomic.Int64
	errors  atomic.Int64

	// mu serializes Reload against Close so a reload can't install a database the
	// service is concurrently shutting down (double-close / leak).
	mu     sync.Mutex
	closed bool

	// index, when true, builds the in-memory provider index on every load so
	// LookupProvider (and /v1/provider) skip the per-lookup MMDB decode.
	index bool

	// closeAfter delays closing a swapped-out DB; overridable in tests.
	closeAfter func(*attribution.DB)
}

// NewService opens and validates the MMDB at path.
func NewService(path string) (*Service, error) { return NewServiceIndexed(path, false) }

// NewServiceIndexed is NewService with the option to build the in-memory provider
// index at load (and on every reload), trading heap for faster identity lookups.
func NewServiceIndexed(path string, index bool) (*Service, error) {
	s := &Service{path: path, index: index}
	db, err := s.load()
	if err != nil {
		return nil, err
	}
	s.closeAfter = func(old *attribution.DB) {
		time.AfterFunc(closeGrace, func() { old.Close() })
	}
	s.db.Store(db)
	return s, nil
}

// load opens, validates, and (if enabled) indexes the database at s.path.
func (s *Service) load() (*attribution.DB, error) {
	db, err := attribution.OpenValidated(s.path)
	if err != nil {
		return nil, err
	}
	if s.index {
		if err := db.BuildIndex(); err != nil {
			db.Close()
			return nil, fmt.Errorf("build index: %w", err)
		}
	}
	return db, nil
}

// Reload opens the (possibly replaced) file at the original path and atomically
// swaps it in. Used by the sync pipeline's atomic-rename + SIGHUP flow.
//
// The swap itself is race-free (atomic.Pointer), but the previous handle must
// NOT be closed synchronously: a concurrent Lookup may have already loaded it
// and be about to read its mmap. Closing immediately would munmap under that
// reader and segfault the process. Instead the old handle is closed after a
// grace period (closeGrace) longer than any in-flight lookup.
func (s *Service) Reload() error {
	// Validate (and index) before swapping: a partially-copied or corrupt
	// replacement is rejected here and the current (good) database keeps serving.
	db, err := s.load()
	if err != nil {
		return fmt.Errorf("reload %s: %w", s.path, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		db.Close() // service is shutting down; don't install a new handle
		return nil
	}
	old := s.db.Swap(db)
	if old != nil {
		s.closeAfter(old)
	}
	return nil
}

// Close releases the current database. After Close, a concurrent Reload will not
// install (or leak) a new handle.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if db := s.db.Load(); db != nil {
		return db.Close()
	}
	return nil
}

// DB returns the currently active database handle.
func (s *Service) DB() *attribution.DB { return s.db.Load() }

// Lookup resolves one IP string and records metrics.
func (s *Service) Lookup(ipStr string) (attribution.Record, bool, error) {
	s.lookups.Add(1)
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		s.errors.Add(1)
		return attribution.Record{}, false, fmt.Errorf("invalid ip %q: %w", ipStr, err)
	}
	rec, found, err := s.db.Load().Lookup(addr)
	if err != nil {
		s.errors.Add(1)
		return attribution.Record{}, false, err
	}
	if found {
		s.hits.Add(1)
	}
	return rec, found, nil
}

// LookupProvider resolves one IP to provider/region only via the fast path,
// recording the same metrics as Lookup.
func (s *Service) LookupProvider(ipStr string) (provider, region string, found bool, err error) {
	s.lookups.Add(1)
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		s.errors.Add(1)
		return "", "", false, fmt.Errorf("invalid ip %q: %w", ipStr, err)
	}
	provider, region, found, err = s.db.Load().LookupProvider(addr)
	if err != nil {
		s.errors.Add(1)
		return "", "", false, err
	}
	if found {
		s.hits.Add(1)
	}
	return provider, region, found, nil
}

// Stats is a snapshot of service counters for /metrics.
type Stats struct {
	Lookups int64
	Hits    int64
	Errors  int64
}

// Stats returns a counter snapshot.
func (s *Service) Stats() Stats {
	return Stats{Lookups: s.lookups.Load(), Hits: s.hits.Load(), Errors: s.errors.Load()}
}
