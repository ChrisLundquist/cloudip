package attribution

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSourceConfinement(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.json"), []byte(`[]`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A secret living outside the source dir.
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("top secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := FileSource{Dir: dir}

	// In-dir ref works.
	rc, err := src.Open(context.Background(), "ok.json")
	if err != nil {
		t.Fatalf("in-dir open failed: %v", err)
	}
	rc.Close()

	// Traversal refs must be rejected, not silently read.
	for _, ref := range []string{"../secret", "../../etc/hostname", "a/../../secret"} {
		if rc, err := src.Open(context.Background(), ref); err == nil {
			b, _ := io.ReadAll(rc)
			rc.Close()
			t.Errorf("ref %q escaped source dir and read %q", ref, b)
		}
	}

	// Absolute ref is confined under Dir (so it can't read /etc/hostname).
	if rc, err := src.Open(context.Background(), "/etc/hostname"); err == nil {
		rc.Close()
		t.Error("absolute ref was not confined to source dir")
	}
}
