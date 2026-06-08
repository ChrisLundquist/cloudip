package attribution

import (
	"fmt"
	"time"
)

// VerifyReport summarizes a tree walk: total networks and a per-provider count.
type VerifyReport struct {
	Networks   int            // total networks with data
	ByProvider map[string]int // network count per provider
	IPv4       int
	IPv6       int

	// Oldest and Newest are the min/max non-zero per-entry synced_at across the
	// tree. They are the zero time when no record carries a timestamp. For
	// reputation data especially, Oldest is the staleness signal an operator
	// should alert on (a feed that stopped updating ages out here).
	Oldest time.Time
	Newest time.Time
}

// Verify walks the whole tree, validates every record decodes, and returns
// aggregate counts. The sync pipeline compares Networks against the previous
// build and fails if it drops by more than an allowed percentage.
func Verify(db *DB) (VerifyReport, error) {
	rep := VerifyReport{ByProvider: map[string]int{}}
	for nr, err := range db.Networks() {
		if err != nil {
			return rep, fmt.Errorf("verify: %w", err)
		}
		if nr.Record.Provider == "" {
			return rep, fmt.Errorf("verify: network %s has empty provider", nr.Network)
		}
		rep.Networks++
		rep.ByProvider[nr.Record.Provider]++
		if nr.Record.IPv6 {
			rep.IPv6++
		} else {
			rep.IPv4++
		}
		if t := nr.Record.SyncedAt; !t.IsZero() {
			if rep.Oldest.IsZero() || t.Before(rep.Oldest) {
				rep.Oldest = t
			}
			if t.After(rep.Newest) {
				rep.Newest = t
			}
		}
	}
	if rep.Networks == 0 {
		return rep, fmt.Errorf("verify: database is empty")
	}
	return rep, nil
}
