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
	"github.com/ChrisLundquist/cloudip/plugins/asn/iptoasn"
)

func runBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	source := fs.String("source", "rezmoss", "feed source: rezmoss (per-provider CC0 files), rezmoss-all (every provider in one file), or direct (provider URLs); with --reputation: direct (default) or mirror (CLOUDIP_REPUTATION_BASE)")
	fixtures := fs.String("fixtures", "", "build from local fixture dir instead of the network")
	providers := fs.String("providers", "", "comma-separated provider subset (default: all registered)")
	out := fs.String("out", "", "output MMDB path (default cloud.mmdb, or reputation.mmdb with --reputation)")
	csvOut := fs.String("csv", "", "also export a CSV to this path")
	recordSize := fs.Int("record-size", 28, "MMDB record size: 24, 28, or 32")
	maxDrop := fs.Float64("max-drop", 0.5, "fail if network count drops more than this fraction vs existing --out")
	maxSkip := fs.Float64("max-skip", 0.25, "fail if more than this fraction of entries are skipped (0 disables)")
	reputation := fs.Bool("reputation", false, "build a reputation DB (Feodo botnet C2, Spamhaus DROP, Tor exits) instead of cloud providers")
	withReputation := fs.Bool("with-reputation", false, "also ingest all reputation feeds into the same database, after the cloud feeds: a reputation hit inside a cloud range enriches that record's categories (--providers still selects cloud plugins only)")
	repSource := fs.String("reputation-source", "direct", "feed source for the --with-reputation feeds: direct (provider URLs) or mirror (CLOUDIP_REPUTATION_BASE); --fixtures overrides both")
	asn := fs.Bool("asn", false, "build an IP->ASN DB (BGP-derived origin AS per range, via iptoasn.com) instead of cloud providers")
	withASN := fs.Bool("with-asn", false, "enrich every record with the origin AS that announces it (ext.asn/ext.as_org), splitting entries at BGP announcement boundaries")
	asnSource := fs.String("asn-source", "direct", "feed source for --asn/--with-asn: direct (iptoasn.com) or mirror (CLOUDIP_ASN_BASE); --fixtures overrides both")
	keepGoing := fs.Bool("keep-going", true, "isolate per-feed failures: skip a feed that fails to fetch/parse and build the rest (the drop/skip guards still protect against mass loss)")
	pins := fs.String("pins", "", "JSON file of {ref: sha256} digests to verify each fetched feed against (fails the build on mismatch)")
	printDigests := fs.Bool("print-digests", false, "print the SHA-256 of each fetched feed (use to populate a --pins file)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// The --source default ("rezmoss") is a cloud source; track whether it was set
	// explicitly so a reputation build can default to "direct" yet still validate
	// (and reject) an explicit cloud-only source instead of silently ignoring it.
	// --reputation-source is tracked the same way so it can be rejected (not
	// silently ignored) outside a --with-reputation build.
	sourceSet, repSourceSet, asnSourceSet := false, false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "source":
			sourceSet = true
		case "reputation-source":
			repSourceSet = true
		case "asn-source":
			asnSourceSet = true
		}
	})
	if *reputation && *withReputation {
		return fmt.Errorf("--reputation and --with-reputation are mutually exclusive: --reputation builds a reputation-only database, --with-reputation adds the reputation feeds to a cloud build")
	}
	if repSourceSet && !*withReputation {
		return fmt.Errorf("--reputation-source only applies with --with-reputation (for --reputation builds, use --source)")
	}
	if *asn && (*reputation || *withReputation || *withASN) {
		return fmt.Errorf("--asn builds a standalone IP->ASN database and cannot combine with --reputation/--with-reputation/--with-asn")
	}
	if *asn && sourceSet {
		return fmt.Errorf("--source does not apply to --asn builds (the table has no rezmoss mirror; use --asn-source or --fixtures)")
	}
	if asnSourceSet && !*asn && !*withASN {
		return fmt.Errorf("--asn-source only applies with --asn or --with-asn")
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

	// Default the output path by mode so a reputation or ASN build never
	// clobbers the cloud database (and the drop-guard reads the right prior file).
	if *out == "" {
		switch {
		case *reputation:
			*out = "reputation.mmdb"
		case *asn:
			*out = "asn.mmdb"
		default:
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
	if *asn {
		plugins, err := attribution.SelectASNPlugins(splitCSV(*providers))
		if err != nil {
			return err
		}
		if len(plugins) == 0 {
			return fmt.Errorf("no ASN plugins registered")
		}
		resolve, shownSrc, err := asnResolver(*asnSource, *fixtures)
		if err != nil {
			return err
		}
		names := make([]string, len(plugins))
		for i, p := range plugins {
			names[i] = p.Name()
		}
		fmt.Fprintf(os.Stderr, "building %s (asn) from [%s] via %s\n", *out, strings.Join(names, ","), shownSrc)
		entries = collect(plugins, wrapResolve(resolve))
	} else if *reputation {
		// Reputation feeds have no rezmoss mirror: read each provider's own URL
		// (the plugins implement DirectPlugin) or local fixtures.
		plugins, err := attribution.SelectReputationPlugins(splitCSV(*providers))
		if err != nil {
			return err
		}
		if len(plugins) == 0 {
			return fmt.Errorf("no reputation plugins registered")
		}
		// Reputation feeds have no rezmoss mirror, so --source is direct by default
		// and the cloud-only rezmoss sources are rejected rather than ignored.
		repSource := "direct"
		if sourceSet {
			repSource = *source
		}
		resolve, shownSrc, err := reputationResolver(repSource, *fixtures)
		if err != nil {
			return err
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

	// --with-reputation appends the reputation stream AFTER the cloud one. The
	// order is load-bearing: Build's merge is first-writer-wins on provider
	// identity, so cloud-first means a reputation /32 nested inside a cloud range
	// enriches that record's categories instead of claiming the prefix for
	// "tor"/"spamhaus" (see TestCategoriesNestedPrefix).
	if *withReputation {
		repPlugins, err := attribution.SelectReputationPlugins(nil)
		if err != nil {
			return err
		}
		if len(repPlugins) == 0 {
			return fmt.Errorf("no reputation plugins registered")
		}
		resolve, shownSrc, err := reputationResolver(*repSource, *fixtures)
		if err != nil {
			return err
		}
		names := make([]string, len(repPlugins))
		for i, p := range repPlugins {
			names[i] = p.Name()
		}
		fmt.Fprintf(os.Stderr, "adding reputation feeds [%s] via %s\n", strings.Join(names, ","), shownSrc)
		entries = attribution.ConcatEntries(entries, collect(repPlugins, wrapResolve(resolve)))
	}

	// --with-asn wraps the (possibly already reputation-concatenated) stream so
	// every record — cloud and reputation alike — gets the origin AS that
	// announces it. Unlike feed failures, a table that can't be fetched fails
	// the build: the drop/skip guards can't see missing ext fields, so there is
	// no safe "publish without enrichment" fallback when it was asked for.
	if *withASN {
		table, shownSrc, err := loadASNTable(ctx, *asnSource, *fixtures, wrapSource)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "enriching with origin ASNs (%d announcements) via %s\n", table.Len(), shownSrc)
		entries = attribution.EnrichASN(entries, table)
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

// feedResolver picks the feed source for registries with no rezmoss mirror
// (reputation, asn) and a label to print. --fixtures always wins (offline
// build). Otherwise: "direct" hits each provider's own URL; "mirror" fetches
// the plugins' relative Refs() from baseEnv (an internal cache). The
// cloud-only rezmoss sources are rejected with a clear error rather than
// silently ignored. kind labels the errors.
func feedResolver(kind, source, fixtures, baseEnv, base string) (attribution.PluginSource, string, error) {
	if fixtures != "" {
		return attribution.FixtureResolver(fixtures), "fixtures:" + fixtures, nil
	}
	switch source {
	case "direct":
		return attribution.DirectResolver(), "direct", nil
	case "mirror":
		if base == "" {
			return nil, "", fmt.Errorf("%s source mirror requires %s to be set (the internal HTTP base to fetch %s feeds from)", kind, baseEnv, kind)
		}
		return attribution.MirrorResolver(base), "mirror:" + base, nil
	case "rezmoss", "rezmoss-all":
		return nil, "", fmt.Errorf("source %s is cloud-only; %s feeds have no rezmoss mirror (use direct, mirror, or --fixtures)", source, kind)
	default:
		return nil, "", fmt.Errorf("unknown %s source %q (want direct, mirror, or --fixtures)", kind, source)
	}
}

// reputationResolver is feedResolver for the reputation registry (reached via
// --source on a --reputation build, or --reputation-source on --with-reputation).
func reputationResolver(source, fixtures string) (attribution.PluginSource, string, error) {
	return feedResolver("reputation", source, fixtures, attribution.ReputationBaseEnv, attribution.ReputationBase())
}

// asnResolver is feedResolver for the ASN registry (--asn builds).
func asnResolver(source, fixtures string) (attribution.PluginSource, string, error) {
	return feedResolver("asn", source, fixtures, attribution.ASNBaseEnv, attribution.ASNBase())
}

// loadASNTable fetches and parses the iptoasn table for --with-asn, honoring
// the same source selection as --asn builds: --fixtures wins, then
// --asn-source direct (the canonical URL) or mirror (CLOUDIP_ASN_BASE + the
// plugin's relative ref). wrapSource applies the digest pin/record wrapper so
// --pins covers the enrichment feed too.
func loadASNTable(ctx context.Context, source, fixtures string, wrapSource func(attribution.Source) attribution.Source) (*attribution.ASNTable, string, error) {
	var (
		src   attribution.Source
		ref   string
		shown string
	)
	relRef := iptoasn.Plugin{}.Refs()[0]
	switch {
	case fixtures != "":
		src, ref, shown = attribution.FileSource{Dir: fixtures}, relRef, "fixtures:"+fixtures
	case source == "direct":
		src, ref, shown = attribution.NewDirectSource(), iptoasn.DirectURL, "direct"
	case source == "mirror":
		base := attribution.ASNBase()
		if base == "" {
			return nil, "", fmt.Errorf("asn source mirror requires %s to be set (the internal HTTP base to fetch the ASN table from)", attribution.ASNBaseEnv)
		}
		src, ref, shown = &attribution.HTTPSource{BaseURL: base}, relRef, "mirror:"+base
	default:
		return nil, "", fmt.Errorf("unknown asn source %q (want direct, mirror, or --fixtures)", source)
	}
	rc, err := wrapSource(src).Open(ctx, ref)
	if err != nil {
		return nil, "", fmt.Errorf("fetch ASN table %s: %w", ref, err)
	}
	defer rc.Close()
	rows, err := iptoasn.ParseTable(rc)
	if err != nil {
		return nil, "", fmt.Errorf("parse ASN table %s: %w", ref, err)
	}
	table := attribution.NewASNTable(rows)
	if table.Len() == 0 {
		return nil, "", fmt.Errorf("ASN table %s contains no routed ranges", ref)
	}
	return table, shown, nil
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
