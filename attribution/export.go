package attribution

import (
	"encoding/csv"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"strconv"
	"strings"
)

// csvHeader is the column order emitted by ExportCSV. Both the human-readable
// CIDR and the integer range bounds are emitted: range joins on integers are
// the fastest pattern in Presto/Trino, while the CIDR stays readable.
var csvHeader = []string{
	"network_cidr", "start_ip_int", "end_ip_int",
	"provider", "region", "services", "ipv6", "source", "synced_at",
}

// ExportCSV walks the database and writes one row per network to w. start_ip_int
// and end_ip_int are decimal integer bounds of the network: for IPv4 they fit a
// BIGINT; for IPv6 they are full 128-bit decimals (use DECIMAL/VARBINARY, or
// split into hi/lo columns warehouse-side).
func ExportCSV(db *DB, w io.Writer) (int, error) {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return 0, fmt.Errorf("write csv header: %w", err)
	}

	count := 0
	for nr, err := range db.Networks() {
		if err != nil {
			return count, err
		}
		start, end := rangeBounds(nr.Network)
		row := []string{
			nr.Network.String(),
			start.String(),
			end.String(),
			nr.Record.Provider,
			nr.Record.Region,
			strings.Join(nr.Record.Services, ","),
			strconv.FormatBool(nr.Record.IPv6),
			nr.Record.Source,
			strconv.FormatInt(nr.Record.SyncedAt.Unix(), 10),
		}
		if nr.Record.SyncedAt.IsZero() {
			row[len(row)-1] = "0"
		}
		if err := cw.Write(row); err != nil {
			return count, fmt.Errorf("write csv row: %w", err)
		}
		count++
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return count, fmt.Errorf("flush csv: %w", err)
	}
	return count, nil
}

// rangeBounds returns the inclusive [first, last] integer addresses covered by a
// prefix. IPv4 addresses produce 32-bit integers; IPv6 produce 128-bit.
func rangeBounds(p netip.Prefix) (start, end *big.Int) {
	p = p.Masked()
	addr := p.Addr()

	var bitLen int
	var raw []byte
	if addr.Is4() {
		bitLen = 32
		a4 := addr.As4()
		raw = a4[:]
	} else {
		bitLen = 128
		a16 := addr.As16()
		raw = a16[:]
	}

	start = new(big.Int).SetBytes(raw)
	hostBits := bitLen - p.Bits()
	// end = start + 2^hostBits - 1
	span := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	span.Sub(span, big.NewInt(1))
	end = new(big.Int).Add(start, span)
	return start, end
}
