package main

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// The console is mounted at /ui/, so the built index must reference assets
// under /ui/assets/. With the Vite default base ("/"), browsers request
// /assets/... at the site root, which is the echo endpoint — the page then
// stays blank. This guards the embedded bundle against that regression.
func TestEmbeddedUIUsesUIBasePath(t *testing.T) {
	raw, err := fs.ReadFile(frontendFS, "frontend/dist/index.html")
	if err != nil {
		t.Fatalf("read embedded index.html: %v", err)
	}
	re := regexp.MustCompile(`src="(/[^"]+\.js)"`)
	m := re.FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatalf("no module script in index.html:\n%s", raw)
	}
	if !strings.HasPrefix(m[1], "/ui/assets/") {
		t.Fatalf("index.html references %q; assets must live under /ui/assets/", m[1])
	}
	uiFS, err := fs.Sub(frontendFS, "frontend/dist")
	if err != nil {
		t.Fatal(err)
	}
	asset := strings.TrimPrefix(m[1], "/ui/")
	if _, err := fs.Stat(uiFS, asset); err != nil {
		t.Fatalf("referenced asset %q missing from embedded bundle: %v", asset, err)
	}
}
