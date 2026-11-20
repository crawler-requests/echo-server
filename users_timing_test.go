package main

import (
	"strings"
	"testing"
	"time"
)

// A missing username must cost the same PBKDF2 work as a wrong password, or
// response timing enumerates accounts.
func TestAuthenticateUser_UnknownUserCostsTheSameWork(t *testing.T) {
	initDB()
	u, err := CreateFirstAdmin("timinguser", "RightPass-123")
	if err != nil && !strings.Contains(err.Error(), "setup") {
		t.Fatalf("setup: %v", err)
	}
	username := "timinguser"
	if u != nil {
		username = u.Username
	}

	const n = 6
	var known, unknown time.Duration
	for i := 0; i < n; i++ {
		s := time.Now()
		_, _ = AuthenticateUser(username, "wrong-password")
		known += time.Since(s)

		s = time.Now()
		_, _ = AuthenticateUser("no-such-account-xyz", "wrong-password")
		unknown += time.Since(s)
	}
	known, unknown = known/n, unknown/n

	// Without the dummy hash this ratio is ~60x. Allow generous noise but
	// fail if a missing account is clearly cheap.
	if unknown*3 < known {
		t.Fatalf("unknown user is much faster than a known one: known=%v unknown=%v", known, unknown)
	}
}
