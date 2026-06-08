package attribution

import (
	"fmt"
	"iter"
	"os"
	"path/filepath"
)

// SyncResult summarizes one atomic build.
type SyncResult struct {
	Path    string
	Count   int          // networks inserted
	Skipped int          // networks skipped (e.g. aliased ranges)
	Report  VerifyReport // post-build tree walk
}

// BuildFile builds entries into an MMDB at path atomically (Section 8): it
// writes to a temp file in the same directory, walks the result to validate it,
// optionally guards against a suspicious drop in network count versus prev, then
// renames into place so readers using auto_reload/SIGHUP see a complete file.
//
// maxDropFrac in (0,1] fails the build if the new network count is below
// (1-maxDropFrac) * prev.Networks. Pass prev == nil to skip the guard (first build).
func BuildFile(entries iter.Seq2[Entry, error], path string, opts BuildOptions, prev *VerifyReport, maxDropFrac float64) (SyncResult, error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return SyncResult{}, fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if we bail before the rename.
	committed := false
	defer func() {
		if !committed {
			os.Remove(tmpPath)
		}
	}()

	stats, err := Build(entries, tmp, opts)
	if err != nil {
		tmp.Close()
		return SyncResult{}, err // disk-full etc. surfaces here; temp is removed
	}
	// fsync the data before the rename so a crash can't leave a renamed-but-empty
	// file. A disk-full condition also surfaces deterministically at Sync.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return SyncResult{}, fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return SyncResult{}, fmt.Errorf("close temp: %w", err)
	}

	// Verify by reopening the file we just wrote.
	db, err := Open(tmpPath)
	if err != nil {
		return SyncResult{}, fmt.Errorf("reopen for verify: %w", err)
	}
	rep, err := Verify(db)
	db.Close()
	if err != nil {
		return SyncResult{}, fmt.Errorf("verify: %w", err)
	}

	if prev != nil && maxDropFrac > 0 && prev.Networks > 0 {
		floor := float64(prev.Networks) * (1 - maxDropFrac)
		if float64(rep.Networks) < floor {
			return SyncResult{}, fmt.Errorf(
				"network count dropped too far: %d < %.0f (prev %d, max drop %.0f%%); refusing to publish",
				rep.Networks, floor, prev.Networks, maxDropFrac*100)
		}
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return SyncResult{}, fmt.Errorf("atomic rename: %w", err)
	}
	committed = true
	// fsync the directory so the rename itself is durable across a crash.
	syncDir(dir)
	return SyncResult{Path: path, Count: stats.Inserted, Skipped: stats.Skipped, Report: rep}, nil
}

// syncDir best-effort fsyncs a directory so a rename within it survives a crash.
// Failures are ignored: not all filesystems support directory fsync, and the
// data file itself is already fsync'd.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}
