package datasets

import (
	"os"
	"testing"

	"github.com/crawler-requests/echo-server/safeurl"
)

// Remote-provider tests stand up httptest servers on 127.0.0.1, which the
// production SSRF guard (rightly) blocks. The override is test-only and
// process-scoped, so it cannot leak into a deployed binary.
func TestMain(m *testing.M) {
	safeurl.AllowPrivateForTests(true)
	// File providers are sandboxed to a data root; point it at the test temp
	// tree so the existing file-provider tests keep exercising real reads.
	// File providers are sandboxed. Tests create their files under t.TempDir(),
	// which lives directly under os.TempDir(), so using that as the root keeps
	// every test's own directory inside the sandbox while still isolating tests
	// from each other (each t.TempDir() is a distinct subdirectory).
	root := os.TempDir()
	SetFileRoot(root)
	code := m.Run()
	os.Exit(code)
}
