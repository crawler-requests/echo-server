package datasets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// File-provider sandbox.
//
// A `file` provider takes a path from the admin API and reads it with
// os.ReadFile. Without a boundary that is an arbitrary-file-read primitive
// (read /etc/passwd, other services' configs, a mounted secret) reachable
// through the same endpoint as an innocent dataset edit — and, on a shared
// host, from a viewer who was mistakenly given admin. The engine therefore
// confines file providers to a data directory.
//
// The root defaults to the dataset cache directory and can be widened
// explicitly by the operator (ECHO_SERVER_DATA_DIR) for deployments that mount
// their tables elsewhere. An absolute path outside the root is refused, as is
// any path whose cleaned form escapes it through "..".
var allowedRoot atomic.Pointer[string]

// SetFileRoot installs the directory file providers may read from. An empty
// value means "no root configured", which disables file providers rather than
// silently allowing every path.
func SetFileRoot(root string) {
	if strings.TrimSpace(root) == "" {
		allowedRoot.Store(nil)
		allowedRootValue = ""
		return
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	allowedRoot.Store(&abs)
	allowedRootValue = abs
}

// allowedRootValue mirrors the atomic pointer for error messages.
var allowedRootValue string

// FileRoot returns the configured root ("" when unset).
func FileRoot() string {
	if p := allowedRoot.Load(); p != nil {
		return *p
	}
	return ""
}

// CheckFilePath validates that p is inside the configured data root and returns
// the cleaned absolute path to read. root may be "" to fall back to the
// process-wide root set by SetFileRoot.
func CheckFilePath(p string) (string, error) {
	return checkFileUnder(p, FileRoot())
}

// checkFileUnder is CheckFilePath with an explicit root, used by a Manager that
// declares its own data directory.
func checkFileUnder(p, root string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errors.New("no path given")
	}
	if root == "" {
		return "", errors.New("file data sources are disabled: set ECHO_SERVER_DATA_DIR to the directory that holds dataset files")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("bad path %q: %w", p, err)
	}
	clean := filepath.Clean(abs)

	// A path is allowed only when it is the root itself or lies beneath it.
	if clean != root && !strings.HasPrefix(clean, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q is outside the data directory (%s)", p, root)
	}
	// Refuse symlinks that resolve outside the root: the string check above
	// sees the link path, not its target.
	if fi, err := os.Lstat(clean); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		real, err := filepath.EvalSymlinks(clean)
		if err != nil {
			return "", fmt.Errorf("bad symlink %q: %w", p, err)
		}
		if real != root && !strings.HasPrefix(real, root+string(os.PathSeparator)) {
			return "", fmt.Errorf("path %q resolves outside the data directory", p)
		}
		return real, nil
	}
	return clean, nil
}
