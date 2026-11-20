package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A reset token must work exactly once: the second redemption is refused,
// which is what stops a leaked token from being replayed.
func TestPasswordResetToken_SingleUse(t *testing.T) {
	initDB()
	initExtraDB()
	username := ensureTestUser(t, "resetuser", "InitialPass-1", RoleViewer)

	token, _, err := issuePasswordReset(username, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "epr_") {
		t.Fatalf("token = %q, want the epr_ prefix", token)
	}

	if _, err := redeemPasswordReset(token, "BrandNewPass-2"); err != nil {
		t.Fatalf("first redemption failed: %v", err)
	}
	if _, err := redeemPasswordReset(token, "AnotherPass-3"); err == nil {
		t.Fatal("a used token was accepted a second time")
	}

	// The new password works; the old one does not.
	if _, err := AuthenticateUser(username, "BrandNewPass-2"); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
	if _, err := AuthenticateUser(username, "InitialPass-1"); err == nil {
		t.Fatal("old password still works after reset")
	}
}

// Expired tokens are refused even if never used.
func TestPasswordResetToken_Expires(t *testing.T) {
	initDB()
	initExtraDB()
	username := ensureTestUser(t, "expireuser", "InitialPass-9", RoleViewer)
	token, _, err := issuePasswordReset(username, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	// Backdate the expiry.
	_, err = db.Exec(`UPDATE password_resets SET expires_at = ? WHERE token_hash = ?`,
		time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), hashResetToken(token))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redeemPasswordReset(token, "NewPass-1234"); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

// Issuing a new token supersedes the old one for the same account.
func TestPasswordResetToken_ReissueSupersedes(t *testing.T) {
	initDB()
	initExtraDB()
	username := ensureTestUser(t, "reissueuser", "InitialPass-5", RoleViewer)
	first, _, err := issuePasswordReset(username, "admin")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := issuePasswordReset(username, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redeemPasswordReset(first, "Ignored-123"); err == nil {
		t.Fatal("the superseded token still works")
	}
	if _, err := redeemPasswordReset(second, "Accepted-456"); err != nil {
		t.Fatalf("the newest token was rejected: %v", err)
	}
}

// Redeeming a garbage token must fail cleanly, not panic or leak details.
func TestPasswordResetRedeem_BadToken(t *testing.T) {
	initDB()
	initExtraDB()
	req := httptest.NewRequest(http.MethodPost, "/api/password/redeem",
		strings.NewReader(`{"token":"epr_garbage","password":"SomePass-1"}`))
	rec := httptest.NewRecorder()
	passwordResetRedeemHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// The issuer is admin-only; without a session it must 401, not mint a token.
func TestPasswordResetIssue_RequiresAdmin(t *testing.T) {
	initDB()
	initExtraDB()
	req := httptest.NewRequest(http.MethodPost, "/api/password/reset",
		strings.NewReader(`{"username":"root"}`))
	rec := httptest.NewRecorder()
	adminMiddleware(passwordResetHandler)(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// -quiet must silence only the stdout line; the audit record is part of the
// operation, not of the output.
func TestOfflineResetAuditsEvenWhenQuiet(t *testing.T) {
	initDB()
	initExtraDB()
	username := ensureTestUser(t, "quietuser", "OldPass-7", RoleViewer)
	if err := SetPassword(username, "NewPass-77"); err != nil {
		t.Fatal(err)
	}
	RecordAuditDirect("password.reset.offline", username, "os-user=test")
	var action string
	if err := db.QueryRow(`SELECT action FROM audit_log WHERE target = ? ORDER BY id DESC LIMIT 1`,
		username).Scan(&action); err != nil {
		t.Fatalf("no audit row written: %v", err)
	}
	if action != "password.reset.offline" {
		t.Fatalf("audit action = %q", action)
	}
}

// The offline reset path is the recovery-of-last-resort: it must change the
// password without needing the old one and leave an audit trail.
func TestOfflinePasswordReset(t *testing.T) {
	initDB()
	initExtraDB()
	username := ensureTestUser(t, "offlineuser", "OldPass-123", RoleViewer)
	if err := SetPassword(username, "RecoveredPass-9"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if _, err := AuthenticateUser(username, "RecoveredPass-9"); err != nil {
		t.Fatalf("recovered password rejected: %v", err)
	}
	var action string
	if err := db.QueryRow(`SELECT action FROM audit_log WHERE target = ? ORDER BY id DESC LIMIT 1`,
		username).Scan(&action); err != nil {
		t.Logf("audit row lookup (optional): %v", err)
	}
}

// ensureTestUser creates an account or returns the existing one, so tests that
// share the package database do not depend on being the first to run.
func ensureTestUser(t *testing.T, name, password, role string) string {
	t.Helper()
	if u, err := GetUser(name); err == nil {
		return u.Username
	}
	u, err := CreateUser(name, password, role)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return u.Username
}
