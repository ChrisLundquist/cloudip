package server

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ChrisLundquist/cloudip/attribution"
)

// TestReloadCorruptKeepsServing covers the partial-copy / corruption case: if the
// file on disk is replaced with a truncated or garbage file, Reload must fail and
// the service must keep serving the previously-loaded good database.
func TestReloadCorruptKeepsServing(t *testing.T) {
	path := buildTestDB(t)
	svc, err := NewService(path)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	// Sanity: good lookup before the corruption.
	if _, found, _ := svc.Lookup("52.94.0.1"); !found {
		t.Fatal("expected hit before reload")
	}

	full, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Deploys must publish via atomic rename (a new inode), never an in-place
	// overwrite — the old DB's mmap still references the original inode, so it
	// keeps serving while Reload inspects the replacement. Model that here.
	swapIn := func(data []byte) {
		t.Helper()
		tmp := path + ".incoming"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}

	// A truncated replacement arrives (interrupted scp/rsync that still renamed).
	swapIn(full[:len(full)/2])
	if err := svc.Reload(); err == nil {
		t.Error("Reload accepted a truncated file")
	}
	// Old DB still serves correctly.
	if _, found, err := svc.Lookup("52.94.0.1"); err != nil || !found {
		t.Errorf("service stopped serving after a failed reload: found=%v err=%v", found, err)
	}

	// A good file is published and reload now succeeds.
	swapIn(full)
	if err := svc.Reload(); err != nil {
		t.Errorf("reload of restored good file failed: %v", err)
	}
	if _, found, _ := svc.Lookup("52.94.0.1"); !found {
		t.Error("expected hit after good reload")
	}
}

// TestStatsCounters asserts the metrics counters reflect actual lookups: hits,
// misses, and parse errors are categorized correctly.
func TestStatsCounters(t *testing.T) {
	svc, err := NewService(buildTestDB(t))
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	svc.Lookup("52.94.0.1")   // hit
	svc.Lookup("52.94.0.2")   // hit
	svc.Lookup("203.0.113.1") // miss (valid IP, not attributed)
	svc.Lookup("not-an-ip")   // error
	svc.Lookup("also bad")    // error

	st := svc.Stats()
	if st.Lookups != 5 {
		t.Errorf("Lookups = %d, want 5", st.Lookups)
	}
	if st.Hits != 2 {
		t.Errorf("Hits = %d, want 2", st.Hits)
	}
	if st.Errors != 2 {
		t.Errorf("Errors = %d, want 2", st.Errors)
	}
}

// TestReloadConcurrentLookup hammers Lookup while Reload swaps the database and
// verifies the atomic.Pointer swap is race-free under -race. The deferred-close
// handoff is verified WITHOUT closing any handle while a reader might still hold
// it: the closeAfter override merely records each swapped-out handle, and the
// recorded handles are closed only after the readers have stopped.
//
// (An earlier version of this test closed swapped-out handles on a 20ms
// time.AfterFunc, which opened a use-after-free window: a reader goroutine could
// still hold the old handle and read its mmap while the timer called Close() and
// munmapped it. That is a test-only timing artifact, not a production bug —
// production keeps a 30s closeGrace that comfortably outlasts any in-flight
// lookup, so a swapped-out handle is never closed under an active reader.)
func TestReloadConcurrentLookup(t *testing.T) {
	path := buildTestDB(t)
	svc, err := NewService(path)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	// Record swapped-out handles instead of closing them on a timer. Closing a
	// handle here, while readers are live, would munmap under an in-flight
	// Lookup; we defer every close until the readers have stopped (see below).
	var (
		swappedMu sync.Mutex
		swapped   []*attribution.DB
	)
	svc.closeAfter = func(old *attribution.DB) {
		swappedMu.Lock()
		swapped = append(swapped, old)
		swappedMu.Unlock()
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Readers.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if _, _, err := svc.Lookup("52.94.0.1"); err != nil {
						t.Errorf("lookup: %v", err)
						return
					}
				}
			}
		}()
	}
	// Reloader.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			select {
			case <-stop:
				return
			default:
				if err := svc.Reload(); err != nil {
					t.Errorf("reload: %v", err)
					return
				}
			}
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Readers have stopped and wg.Wait has joined them, so no goroutine can hold
	// a swapped-out handle anymore. Closing the recorded handles is now safe —
	// no use-after-free window. Assert the handoff actually happened.
	swappedMu.Lock()
	defer swappedMu.Unlock()
	if len(swapped) == 0 {
		t.Error("expected some swapped-out handles to be handed off for deferred close")
	}
	for _, old := range swapped {
		old.Close()
	}
}
