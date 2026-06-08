package server

import (
	"os"
	"sync"
	"sync/atomic"
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

// TestReloadConcurrentLookup hammers Lookup while Reload swaps the database, with
// the grace-close shortened so swapped-out handles actually get closed during
// the test. Run under -race; it must not data-race or segfault (the bug was an
// immediate Close() munmapping under in-flight lookups).
func TestReloadConcurrentLookup(t *testing.T) {
	path := buildTestDB(t)
	svc, err := NewService(path)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	// Close swapped-out handles quickly (but still after any in-flight lookup),
	// so the test exercises the deferred-close path rather than leaking handles.
	var closes atomic.Int64
	svc.closeAfter = func(old *attribution.DB) {
		time.AfterFunc(20*time.Millisecond, func() {
			old.Close()
			closes.Add(1)
		})
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

	// Give the AfterFunc closers time to fire; the process must stay alive.
	time.Sleep(60 * time.Millisecond)
	if closes.Load() == 0 {
		t.Error("expected some swapped-out handles to be closed")
	}
}
