package attribution

import (
	"context"
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
	BaseURL string       // optional; joined with ref when set
	Client  *http.Client // optional; defaults to a 30s-timeout client
}

// rezmossRawBase is the default CC0 mirror of per-provider IP-range files.
// Upstream provider terms still apply; the mirror itself is public domain.
const rezmossRawBase = "https://raw.githubusercontent.com/rezmoss/cloud-provider-ip-addresses/main/"

// NewRezmossSource returns an HTTPSource pinned to the rezmoss CC0 mirror.
func NewRezmossSource() *HTTPSource { return &HTTPSource{BaseURL: rezmossRawBase} }

// NewDirectSource returns an HTTPSource that treats refs as absolute URLs.
func NewDirectSource() *HTTPSource { return &HTTPSource{} }

func (s *HTTPSource) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Open fetches ref over HTTP. The caller owns closing the returned stream.
func (s *HTTPSource) Open(ctx context.Context, ref string) (io.ReadCloser, error) {
	url := ref
	if s.BaseURL != "" {
		url = strings.TrimSuffix(s.BaseURL, "/") + "/" + strings.TrimPrefix(ref, "/")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %q: %w", url, err)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %q: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("fetch %q: unexpected status %s", url, resp.Status)
	}
	return resp.Body, nil
}

// FileSource resolves refs as files under Dir (or as absolute paths when Dir is
// empty). It is what tests use to inject checked-in fixtures, and what ops use
// to build from a pre-downloaded local cache.
type FileSource struct {
	Dir string
}

// Open opens ref as a file. A ref may use forward slashes on any OS. When Dir is
// set, the ref is confined to it: a ref that escapes via ".." (or an absolute
// path) is rejected rather than silently reading outside the fixture/cache dir.
func (s FileSource) Open(_ context.Context, ref string) (io.ReadCloser, error) {
	clean := filepath.FromSlash(path.Clean("/" + strings.TrimPrefix(ref, "/")))
	p := clean
	if s.Dir != "" {
		// clean is rooted at "/", so Join drops any leading ".." — confining it.
		p = filepath.Join(s.Dir, clean)
		rel, err := filepath.Rel(s.Dir, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("ref %q escapes source dir %q", ref, s.Dir)
		}
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("open fixture %q: %w", p, err)
	}
	return f, nil
}
