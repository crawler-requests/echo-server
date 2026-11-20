package iplookup_test

import (
	"os"
	"testing"

	"github.com/crawler-requests/echo-server/safeurl"
)

// The chain tests stand up httptest servers on 127.0.0.1, which the production
// SSRF guard blocks on purpose. The override is test-only and process-scoped.
func TestMain(m *testing.M) {
	safeurl.AllowPrivateForTests(true)
	os.Exit(m.Run())
}
