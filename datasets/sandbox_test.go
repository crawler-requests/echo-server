package datasets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckFilePath_RejectsEscapes(t *testing.T) {
	root := t.TempDir()
	SetFileRoot(root)
	t.Cleanup(func() { SetFileRoot("") })

	inside := filepath.Join(root, "ok.txt")
	if err := os.WriteFile(inside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := checkFileUnder(inside, root); err != nil {
		t.Fatalf("in-root file rejected: %v", err)
	}
	if _, err := checkFileUnder(root, root); err != nil {
		t.Fatalf("the root itself must be allowed: %v", err)
	}

	for _, p := range []string{
		"/etc/passwd",
		filepath.Join(root, "..", "escape.txt"),
		"/proc/self/environ",
	} {
		if _, err := checkFileUnder(p, root); err == nil {
			t.Errorf("checkFileUnder(%q) allowed an escape", p)
		}
	}

	// No root configured: file providers are disabled, not silently open.
	if _, err := checkFileUnder("/etc/passwd", ""); err == nil {
		t.Error("an empty root allowed a read")
	}
}

func TestCheckFilePath_RejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	SetFileRoot(root)
	t.Cleanup(func() { SetFileRoot("") })

	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := checkFileUnder(link, root); err == nil {
		t.Fatal("a symlink out of the root was allowed")
	}
}
