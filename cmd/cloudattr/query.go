package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func runLookup(args []string) error {
	fs := flag.NewFlagSet("lookup", flag.ContinueOnError)
	in := fs.String("in", "cloud.mmdb", "MMDB path")
	format := fs.String("format", "text", "output format: text or json")
	file := fs.String("f", "", "read IPs from a file (one per line), or '-' for stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ips := fs.Args()
	if *file != "" {
		fileIPs, err := readIPsFile(*file)
		if err != nil {
			return err
		}
		ips = append(ips, fileIPs...)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no IPs given (pass IPs as args or use -f FILE)")
	}

	db, err := attribution.Open(*in)
	if err != nil {
		return err
	}
	defer db.Close()

	enc := json.NewEncoder(os.Stdout)
	failures := 0
	for _, ip := range ips {
		rec, found, err := db.LookupString(ip)
		if err != nil {
			failures++
			if *format == "json" {
				_ = enc.Encode(map[string]any{"ip": ip, "found": false, "error": err.Error()})
			} else {
				fmt.Fprintf(os.Stderr, "skip %s: %v\n", ip, err)
			}
			continue
		}
		switch *format {
		case "json":
			out := map[string]any{"ip": ip, "found": found}
			if found {
				out["record"] = recordMap(rec)
			}
			if err := enc.Encode(out); err != nil {
				return err
			}
		default:
			if !found {
				fmt.Printf("%s\tnot attributed\n", ip)
				continue
			}
			tags := strings.Join(rec.Services, ",")
			if len(rec.Categories) > 0 {
				tags = strings.Join(rec.Categories, ",")
			}
			fmt.Printf("%s\t%s\t%s\t%s\n", ip, rec.Provider, rec.Region, tags)
		}
	}
	// A miss is a valid answer, but a malformed IP is a failure; if every input
	// failed, exit non-zero so scripts notice.
	if failures > 0 && failures == len(ips) {
		return fmt.Errorf("all %d lookups failed", failures)
	}
	return nil
}

func recordMap(r attribution.Record) map[string]any {
	var synced int64
	if !r.SyncedAt.IsZero() {
		synced = r.SyncedAt.Unix()
	}
	return map[string]any{
		"provider": r.Provider, "region": r.Region, "services": r.Services,
		"categories": r.Categories, "ipv6": r.IPv6, "source": r.Source,
		"synced_at": synced, "ext": r.Ext,
	}
}

func readIPsFile(path string) ([]string, error) {
	f := os.Stdin
	if path != "-" {
		var err error
		f, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
	}
	var ips []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips = append(ips, line)
	}
	return ips, sc.Err()
}

func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	in := fs.String("in", "cloud.mmdb", "MMDB path")
	out := fs.String("out", "-", "CSV output path, or '-' for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return exportCSVFile(*in, *out)
}

func exportCSVFile(in, out string) error {
	db, err := attribution.Open(in)
	if err != nil {
		return err
	}
	defer db.Close()

	// stdout: stream directly.
	if out == "-" {
		_, err := attribution.ExportCSV(db, os.Stdout)
		return err
	}

	// File: write to a temp file, fsync, and atomically rename, so a disk-full
	// or crash mid-export never leaves a truncated CSV that looks complete.
	tmp, err := os.CreateTemp(filepath.Dir(out), filepath.Base(out)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			os.Remove(tmpPath)
		}
	}()

	n, err := attribution.ExportCSV(db, tmp)
	if err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, out); err != nil {
		return err
	}
	committed = true
	fmt.Fprintf(os.Stderr, "exported %d rows\n", n)
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	in := fs.String("in", "cloud.mmdb", "MMDB path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := attribution.Open(*in)
	if err != nil {
		return err
	}
	defer db.Close()

	rep, err := attribution.Verify(db)
	if err != nil {
		return err
	}
	md := db.Metadata()
	fmt.Printf("database_type: %s\n", md.DatabaseType)
	fmt.Printf("build_epoch:   %d\n", db.BuildTime().Unix())
	fmt.Printf("record_size:   %d\n", md.RecordSize)
	fmt.Printf("networks:      %d (%d v4 / %d v6)\n", rep.Networks, rep.IPv4, rep.IPv6)
	if !rep.Oldest.IsZero() {
		fmt.Printf("entry age:     oldest %s (%s ago), newest %s\n",
			rep.Oldest.Format("2006-01-02"), humanAge(rep.Oldest), rep.Newest.Format("2006-01-02"))
	}
	for prov, n := range rep.ByProvider {
		fmt.Printf("  %-8s %d\n", prov, n)
	}
	return nil
}

// humanAge renders how long ago t was, coarsely (days).
func humanAge(t time.Time) string {
	d := time.Since(t)
	if d < 24*time.Hour {
		return "today"
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
