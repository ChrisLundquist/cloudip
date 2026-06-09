package attribution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// HTTPSource fetches refs as URLs. With BaseURL set, a ref is resolved relative
// to it (used for the rezmoss CC0 mirror, where refs are repo-relative paths
// like "aws/ip-ranges.json"); with BaseURL empty, the ref must be an absolute
// URL (used for --source direct, where plugins return provider URLs).
type HTTPSource struct {
	BaseURL  string        // optional; joined with ref when set
	Client   *http.Client  // optional; defaults to a 30s-timeout client
	Attempts int           // optional; total tries on transient failures (default 3)
	Backoff  time.Duration // optional; base backoff between tries (default 500ms)
}

// rezmossRawBase is the default CC0 mirror of per-provider IP-range files.
// Upstream provider terms still apply; the mirror itself is public domain.
const rezmossRawBase = "https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/"

// RezmossBaseEnv overrides the rezmoss base URL, so an internal mirror or an
// air-gapped HTTP cache can be used without forking. The value should end in a
// path the per-provider refs hang off of (a trailing slash is normalized).
const RezmossBaseEnv = "CLOUDIP_REZMOSS_BASE"

// RezmossBase returns the effective rezmoss base URL: the CLOUDIP_REZMOSS_BASE
// override if set, else the canonical mirror.
func RezmossBase() string {
	if v := strings.TrimSpace(os.Getenv(RezmossBaseEnv)); v != "" {
		return v
	}
	return rezmossRawBase
}

// NewRezmossSource returns an HTTPSource pinned to the rezmoss mirror (or its
// CLOUDIP_REZMOSS_BASE override).
func NewRezmossSource() *HTTPSource { return &HTTPSource{BaseURL: RezmossBase()} }

// ReputationBaseEnv repoints reputation feeds — which have no rezmoss mirror — at
// an internal HTTP cache, the analogue of RezmossBaseEnv for cloud feeds. The
// build reads it when `--reputation --source mirror` is selected, fetching each
// plugin's relative Refs() (e.g. "tor/exit-list.txt") from this base.
const ReputationBaseEnv = "CLOUDIP_REPUTATION_BASE"

// ReputationBase returns the CLOUDIP_REPUTATION_BASE override, or "" if unset.
func ReputationBase() string { return strings.TrimSpace(os.Getenv(ReputationBaseEnv)) }

// ASNBaseEnv repoints the ASN feed — which, like reputation, has no rezmoss
// mirror — at an internal HTTP cache, for `--asn`/`--with-asn` with
// `--asn-source mirror`. The plugins' relative Refs() are fetched from it.
const ASNBaseEnv = "CLOUDIP_ASN_BASE"

// ASNBase returns the CLOUDIP_ASN_BASE override, or "" if unset.
func ASNBase() string { return strings.TrimSpace(os.Getenv(ASNBaseEnv)) }

// NewDirectSource returns an HTTPSource that treats refs as absolute URLs.
func NewDirectSource() *HTTPSource { return &HTTPSource{} }

func (s *HTTPSource) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Open fetches ref over HTTP, retrying transient failures (network errors and
// 5xx / 429) with backoff so a daily sync survives a flaky mirror. The caller
// owns closing the returned stream. A non-retryable status (e.g. 404) fails fast.
func (s *HTTPSource) Open(ctx context.Context, ref string) (io.ReadCloser, error) {
	url := ref
	if s.BaseURL != "" {
		url = strings.TrimSuffix(s.BaseURL, "/") + "/" + strings.TrimPrefix(ref, "/")
	}

	attempts := s.Attempts
	if attempts <= 0 {
		attempts = 3
	}
	backoff := s.Backoff
	if backoff <= 0 {
		backoff = 500 * time.Millisecond
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff * time.Duration(attempt-1)):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("build request for %q: %w", url, err) // not retryable
		}
		resp, err := s.client().Do(req)
		if err != nil {
			lastErr = fmt.Errorf("fetch %q: %w", url, err)
			continue // network error: retry
		}
		if resp.StatusCode == http.StatusOK {
			return resp.Body, nil
		}
		resp.Body.Close()
		if !retryableStatus(resp.StatusCode) {
			return nil, fmt.Errorf("fetch %q: unexpected status %s", url, resp.Status)
		}
		lastErr = fmt.Errorf("fetch %q: status %s", url, resp.Status)
	}
	return nil, fmt.Errorf("after %d attempts: %w", attempts, lastErr)
}

// retryableStatus reports whether an HTTP status warrants a retry: 429 and 5xx
// are transient; other 4xx are caller errors that won't improve on retry.
func retryableStatus(code int) bool {
	return code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500
}

// DigestSource wraps another Source to compute the SHA-256 of each fetched feed,
// optionally verifying it against a pinned digest. It buffers the whole feed in
// memory. This is a defense against a compromised or hijacked mirror silently
// injecting networks: record the digests once, pin them, and a changed payload
// fails the build instead of shipping.
type DigestSource struct {
	Inner  Source
	Pins   map[string]string           // optional ref -> expected lowercase hex sha256
	Record func(ref, sha256hex string) // optional, called with each computed digest
}

// Open fetches ref through Inner, hashes the body, records/verifies the digest,
// and returns a reader over the buffered bytes.
func (d DigestSource) Open(ctx context.Context, ref string) (io.ReadCloser, error) {
	rc, err := d.Inner.Open(ctx, ref)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return nil, fmt.Errorf("read %s for digest: %w", ref, err)
	}
	sum := sha256.Sum256(data)
	hexsum := hex.EncodeToString(sum[:])
	if d.Record != nil {
		d.Record(ref, hexsum)
	}
	if want, ok := d.Pins[ref]; ok && !strings.EqualFold(want, hexsum) {
		return nil, fmt.Errorf("integrity check failed for %s: got %s, pinned %s", ref, hexsum, want)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// FileSource resolves refs as files under Dir (or as absolute paths when Dir is
// empty). It is what tests use to inject checked-in fixtures, and what ops use
// to build from a pre-downloaded local cache.
type FileSource struct {
	Dir string
}

// Open opens ref as a file. A ref may use forward slashes on any OS. When Dir is
// set, the ref is confined to it via os.OpenInRoot, which rejects escapes — not
// just lexical ".."/absolute paths but symlinks that point outside Dir — at the
// syscall level. With Dir empty, ref is opened directly (trusted absolute path).
func (s FileSource) Open(_ context.Context, ref string) (io.ReadCloser, error) {
	if s.Dir == "" {
		f, err := os.Open(filepath.FromSlash(ref))
		if err != nil {
			return nil, fmt.Errorf("open fixture %q: %w", ref, err)
		}
		return f, nil
	}
	// Make ref a clean path relative to Dir (drop any leading slash so it isn't
	// treated as absolute), then let OpenInRoot enforce confinement.
	rel := filepath.FromSlash(strings.TrimPrefix(path.Clean("/"+ref), "/"))
	if rel == "" {
		rel = "."
	}
	f, err := os.OpenInRoot(s.Dir, rel)
	if err != nil {
		return nil, fmt.Errorf("open fixture %q in %q: %w", ref, s.Dir, err)
	}
	return f, nil
}
