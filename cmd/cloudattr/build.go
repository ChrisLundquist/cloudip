package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"iter"
	"os"
	"strings"
	"time"

	"github.com/ChrisLundquist/cloudip/attribution"
)

func runBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	source := fs.String("source", "rezmoss", "feed source: rezmoss (per-provider CC0 files), rezmoss-all (every provider in one file), or direct (provider URLs)")
	fixtures := fs.String("fixtures", "", "build from local fixture dir instead of the network")
	providers := fs.String("providers", "", "comma-separated provider subset (default: all registered)")
	out := fs.String("out", "", "output MMDB path (default cloud.mmdb, or reputation.mmdb with --reputation)")
	csvOut := fs.String("csv", "", "also export a CSV to this path")
	recordSize := fs.Int("record-size", 28, "MMDB record size: 24, 28, or 32")
	maxDrop := fs.Float64("max-drop", 0.5, "fail if network count drops more than this fraction vs existing --out")
	maxSkip := fs.Float64("max-skip", 0.25, "fail if more than this fraction of entries are skipped (0 disables)")
	reputation := fs.Bool("reputation", false, "build a reputation DB (Feodo botnet C2, Spamhaus DROP, Tor exits) instead of cloud providers")
	keepGoing := fs.Bool("keep-going", true, "isolate per-feed failures: skip a feed that fails to fetch/parse and build the rest (the drop/skip guards still protect against mass loss)")
	pins := fs.String("pins", "", "JSON file of {ref: sha256} digests to verify each fetched feed against (fails the build on mismatch)")
	printDigests := fs.Bool("print-digests", false, "print the SHA-256 of each fetched feed (use to populate a --pins file)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pinMap, record, err := digestOptions(*pins, *printDigests)
	if err != nil {
		return err
	}
	digest := pinMap != nil || record != nil
	wrapResolve := func(r attribution.PluginSource) attribution.PluginSource {
		if !digest {
			return r
		}
		return attribution.WithDigest(r, pinMap, record)
	}
	wrapSource := func(s attribution.Source) attribution.Source {
		if !digest {
			return s
		}
		return attribution.DigestSource{Inner: s, Pins: pinMap, Record: record}
	}

	// Default the output path by mode so a reputation build never clobbers the
	// cloud database (and the drop-guard below reads the right prior file).
	if *out == "" {
		if *reputation {
			*out = "reputation.mmdb"
		} else {
			*out = "cloud.mmdb"
		}
	}

	ctx := context.Background()

	// Read the existing DB's count first so the atomic build can guard a drop.
	var prev *attribution.VerifyReport
	if r, err := verifyCount(*out); err == nil {
		prev = &r
	}

	// collect chooses fail-fast vs per-feed isolation. On isolation, a failing
	// feed is logged and skipped; the drop/skip guards below still protect publish.
	var failures []attribution.FeedFailure
	collect := func(plugins []attribution.Plugin, resolve attribution.PluginSource) iter.Seq2[attribution.Entry, error] {
		if !*keepGoing {
			return attribution.Collect(ctx, plugins, resolve)
		}
		return attribution.CollectResilient(ctx, plugins, resolve, func(f attribution.FeedFailure) {
			failures = append(failures, f)
			fmt.Fprintf(os.Stderr, "warning: skipping feed %s\n", f)
		})
	}

	// rezmoss-all consumes every provider from one unified file; --providers
	// filters by the record's provider field (not the plugin registry), so it
	// can subset to providers we ship no native plugin for (cloudflare, etc.).
	var entries iter.Seq2[attribution.Entry, error]
	if *reputation {
		// Reputation feeds have no rezmoss mirror: read each provider's own URL
		// (the plugins implement DirectPlugin) or local fixtures.
		plugins, err := attribution.SelectReputationPlugins(splitCSV(*providers))
		if err != nil {
			return err
		}
		if len(plugins) == 0 {
			return fmt.Errorf("no reputation plugins registered")
		}
		resolve := attribution.DirectResolver()
		shownSrc := "direct"
		if *fixtures != "" {
			resolve = attribution.FixtureResolver(*fixtures)
			shownSrc = "fixtures:" + *fixtures
		}
		names := make([]string, len(plugins))
		for i, p := range plugins {
			names[i] = p.Name()
		}
		fmt.Fprintf(os.Stderr, "building %s (reputation) from [%s] via %s\n", *out, strings.Join(names, ","), shownSrc)
		entries = collect(plugins, wrapResolve(resolve))
	} else if *source == "rezmoss-all" {
		filter := splitCSV(*providers)
		src := wrapSource(attribution.NewRezmossSource())
		if *fixtures != "" {
			src = wrapSource(attribution.FileSource{Dir: *fixtures})
		}
		shown := "all"
		if len(filter) > 0 {
			shown = strings.Join(filter, ",")
		}
		fmt.Fprintf(os.Stderr, "building %s from providers [%s] via %s\n", *out, shown, describeSource(*source, *fixtures))
		entries = attribution.CollectRezmossAll(ctx, src, filter)
	} else {
		plugins, err := attribution.SelectPlugins(splitCSV(*providers))
		if err != nil {
			return err
		}
		if len(plugins) == 0 {
			return fmt.Errorf("no provider plugins registered")
		}

		var resolve attribution.PluginSource
		switch {
		case *fixtures != "":
			resolve = attribution.FixtureResolver(*fixtures)
		case *source == "rezmoss":
			resolve = attribution.RezmossResolver()
		case *source == "direct":
			resolve = attribution.DirectResolver()
		default:
			return fmt.Errorf("unknown --source %q (want rezmoss, rezmoss-all, or direct)", *source)
		}

		names := make([]string, len(plugins))
		for i, p := range plugins {
			names[i] = p.Name()
		}
		fmt.Fprintf(os.Stderr, "building %s from providers [%s] via %s\n", *out, strings.Join(names, ","), describeSource(*source, *fixtures))
		entries = collect(plugins, wrapResolve(resolve))
	}

	opts := attribution.BuildOptions{
		RecordSize: *recordSize,
		BuildEpoch: uint64(time.Now().Unix()),
	}

	res, err := attribution.BuildFile(entries, *out, opts, prev, *maxDrop, *maxSkip)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s: %d inserted, %d skipped, %d networks (%d v4 / %d v6)\n",
		res.Path, res.Count, res.Skipped, res.Report.Networks, res.Report.IPv4, res.Report.IPv6)
	for prov, n := range res.Report.ByProvider {
		fmt.Fprintf(os.Stderr, "  %-8s %d\n", prov, n)
	}
	if len(failures) > 0 {
		// Published best-effort: the data passed the drop/skip guards, but flag the
		// missing feeds loudly so a cron run is visibly degraded.
		fmt.Fprintf(os.Stderr, "DEGRADED: %d feed(s) skipped:\n", len(failures))
		for _, f := range failures {
			fmt.Fprintf(os.Stderr, "  - %s\n", f)
		}
	}

	if *csvOut != "" {
		if err := exportCSVFile(*out, *csvOut); err != nil {
			return fmt.Errorf("csv export: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *csvOut)
	}
	return nil
}

// digestOptions loads the optional pins file and builds the digest-print callback.
func digestOptions(pinsPath string, printDigests bool) (map[string]string, func(ref, sha string), error) {
	var pinMap map[string]string
	if pinsPath != "" {
		b, err := os.ReadFile(pinsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read pins: %w", err)
		}
		if err := json.Unmarshal(b, &pinMap); err != nil {
			return nil, nil, fmt.Errorf("parse pins %q: %w", pinsPath, err)
		}
	}
	var record func(ref, sha string)
	if printDigests {
		record = func(ref, sha string) { fmt.Fprintf(os.Stderr, "digest %s  %s\n", sha, ref) }
	}
	return pinMap, record, nil
}

func describeSource(source, fixtures string) string {
	if fixtures != "" {
		return "fixtures:" + fixtures
	}
	return source
}

// verifyCount opens an existing MMDB and returns its walk report, if present.
func verifyCount(path string) (attribution.VerifyReport, error) {
	db, err := attribution.Open(path)
	if err != nil {
		return attribution.VerifyReport{}, err
	}
	defer db.Close()
	return attribution.Verify(db)
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
