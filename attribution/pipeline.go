package attribution

import (
	"context"
	"fmt"
	"io"
	"iter"
	"sort"
)

// ParseFunc normalizes one already-fetched feed into entries. A plugin's native
// Parse is one ParseFunc; the shared rezmoss decoder is another.
type ParseFunc func(ref string, r io.Reader) iter.Seq2[Entry, error]

// Feed is one unit of work for the builder: open Ref from Source, hand the bytes
// to Parse. Bundling the parser with the ref is what lets --source rezmoss use a
// uniform decoder while --source direct uses each plugin's native Parse.
type Feed struct {
	Ref    string
	Source Source
	Parse  ParseFunc
}

// PluginSource resolves a plugin to the feeds the builder should ingest for it.
// This is the seam that makes rezmoss/direct/fixture modes interchangeable and
// lets direct mode fall back to rezmoss per provider (the hybrid default).
type PluginSource func(p Plugin) []Feed

// RezmossResolver reads each provider's normalized file from the rezmoss CC0
// mirror and parses it with the uniform rezmoss schema.
func RezmossResolver() PluginSource {
	src := NewRezmossSource()
	return func(p Plugin) []Feed { return rezmossFeeds(p, src) }
}

// DirectResolver reads each provider's own URLs with the plugin's native parser,
// falling back to the rezmoss mirror for providers without a stable direct URL.
func DirectResolver() PluginSource {
	direct := NewDirectSource()
	rezmoss := NewRezmossSource()
	return func(p Plugin) []Feed {
		dp, ok := p.(DirectPlugin)
		if !ok {
			return rezmossFeeds(p, rezmoss) // no direct URL: hybrid fallback
		}
		refs := dp.DirectRefs()
		feeds := make([]Feed, len(refs))
		for i, ref := range refs {
			feeds[i] = Feed{Ref: ref, Source: direct, Parse: p.Parse}
		}
		return feeds
	}
}

// FixtureResolver reads each plugin's native Refs() from a local FileSource and
// parses them with the plugin's native parser. Used by tests and offline builds
// against checked-in native provider files.
func FixtureResolver(dir string) PluginSource {
	src := FileSource{Dir: dir}
	return func(p Plugin) []Feed {
		refs := p.Refs()
		feeds := make([]Feed, len(refs))
		for i, ref := range refs {
			feeds[i] = Feed{Ref: ref, Source: src, Parse: p.Parse}
		}
		return feeds
	}
}

// rezmossFeeds builds feeds for a plugin against the rezmoss mirror, using the
// uniform rezmoss decoder tagged with the plugin's provider name.
func rezmossFeeds(p Plugin, src Source) []Feed {
	refs := RezmossRefs(p)
	parse := ParseRezmoss(p.Name())
	feeds := make([]Feed, len(refs))
	for i, ref := range refs {
		feeds[i] = Feed{Ref: ref, Source: src, Parse: parse}
	}
	return feeds
}

// WithDigest wraps a resolver so every feed's Source is wrapped in a
// DigestSource with the given pins/record. Use it to hash and optionally verify
// all feeds in a build regardless of which resolver produced them.
func WithDigest(resolve PluginSource, pins map[string]string, record func(ref, sha string)) PluginSource {
	return func(p Plugin) []Feed {
		feeds := resolve(p)
		for i := range feeds {
			feeds[i].Source = DigestSource{Inner: feeds[i].Source, Pins: pins, Record: record}
		}
		return feeds
	}
}

// Collect ingests every feed for the given plugins and yields a single
// normalized entry stream. The builder owns IO here; each ParseFunc stays pure.
// Open/parse failures are yielded as errors; Build aborts on the first one.
func Collect(ctx context.Context, plugins []Plugin, resolve PluginSource) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		for _, p := range plugins {
			for _, f := range resolve(p) {
				if !collectFeed(ctx, p.Name(), f, yield) {
					return
				}
			}
		}
	}
}

// FeedFailure records a feed that could not be ingested (open or parse error).
type FeedFailure struct {
	Provider string
	Ref      string
	Err      error
}

func (f FeedFailure) String() string {
	return fmt.Sprintf("%s (%s): %v", f.Provider, f.Ref, f.Err)
}

// CollectResilient is like Collect but isolates per-feed failures: an open or
// parse error for one feed is reported to onFail and that feed is skipped, while
// entries from healthy feeds still flow. Each feed is buffered, so a feed that
// errors partway (e.g. a truncated download) contributes nothing rather than a
// partial set. Callers pair this with the drop/skip guards in BuildFile to refuse
// publishing when too much data is lost.
func CollectResilient(ctx context.Context, plugins []Plugin, resolve PluginSource, onFail func(FeedFailure)) iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		for _, p := range plugins {
			for _, f := range resolve(p) {
				buf, err := bufferFeed(ctx, f)
				if err != nil {
					if onFail != nil {
						onFail(FeedFailure{Provider: p.Name(), Ref: f.Ref, Err: err})
					}
					continue // isolate: skip this feed, keep the others
				}
				for _, e := range buf {
					if !yield(e, nil) {
						return
					}
				}
			}
		}
	}
}

// bufferFeed reads a whole feed into memory, returning its entries only if the
// feed parses cleanly end-to-end; any error discards the partial result.
func bufferFeed(ctx context.Context, f Feed) ([]Entry, error) {
	rc, err := f.Source.Open(ctx, f.Ref)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var out []Entry
	for e, perr := range f.Parse(f.Ref, rc) {
		if perr != nil {
			return nil, perr
		}
		out = append(out, e)
	}
	return out, nil
}

// collectFeed opens one feed and streams its parsed entries, always closing the
// reader. It returns false if the consumer asked to stop.
func collectFeed(ctx context.Context, provider string, f Feed, yield func(Entry, error) bool) bool {
	rc, err := f.Source.Open(ctx, f.Ref)
	if err != nil {
		return yield(Entry{}, fmt.Errorf("%s: open %s: %w", provider, f.Ref, err))
	}
	defer rc.Close()
	for e, perr := range f.Parse(f.Ref, rc) {
		if perr != nil {
			if !yield(Entry{}, fmt.Errorf("%s: parse %s: %w", provider, f.Ref, perr)) {
				return false
			}
			continue
		}
		if !yield(e, nil) {
			return false
		}
	}
	return true
}

// SelectPlugins returns the registered cloud plugins named in `names`, or all of
// them when `names` is empty (see selectFrom).
func SelectPlugins(names []string) ([]Plugin, error) {
	return selectFrom(Plugins(), names)
}

// SelectReputationPlugins is SelectPlugins over the reputation registry.
func SelectReputationPlugins(names []string) ([]Plugin, error) {
	return selectFrom(ReputationPlugins(), names)
}

// selectFrom returns the plugins named in `names` from reg, or all of them
// (sorted by name for deterministic builds) when `names` is empty. It errors on
// an unknown name.
func selectFrom(reg map[string]Plugin, names []string) ([]Plugin, error) {
	if len(names) == 0 {
		out := make([]Plugin, 0, len(reg))
		for _, p := range reg {
			out = append(out, p)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
		return out, nil
	}
	out := make([]Plugin, 0, len(names))
	for _, n := range names {
		p, ok := reg[n]
		if !ok {
			return nil, fmt.Errorf("unknown provider plugin %q", n)
		}
		out = append(out, p)
	}
	return out, nil
}
