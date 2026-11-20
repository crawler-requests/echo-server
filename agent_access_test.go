package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setAgentPolicy(t *testing.T, v string) {
	t.Helper()
	prev := GetConfig("agent_access")
	if err := SetConfig("agent_access", v); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetConfig("agent_access", prev) })
}

// The default is "token": an unset policy must not silently expose /ip to the
// internet. This is the bug the policy exists to close.
func TestAgentAccess_DefaultsToToken(t *testing.T) {
	initDB()
	if got := agentAccess(); got != agentToken {
		t.Fatalf("default policy = %q, want %q", got, agentToken)
	}
}

func TestAgentAccess_PublicAllowsAnonymous(t *testing.T) {
	initDB()
	setAgentPolicy(t, agentPublic)
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	rec := httptest.NewRecorder()
	if !agentAuthorized(rec, req) {
		t.Fatal("public policy rejected an anonymous request")
	}
}

func TestAgentAccess_TokenRejectsAnonymous(t *testing.T) {
	initDB()
	initExtraDB()
	setAgentPolicy(t, agentToken)
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	rec := httptest.NewRecorder()
	if agentAuthorized(rec, req) {
		t.Fatal("token policy accepted an anonymous request")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	// The body must tell the caller what to do, since an agent reads it.
	body := rec.Body.String()
	if !strings.Contains(body, "X-API-Key") || !strings.Contains(body, "/ui/access") {
		t.Fatalf("refusal body lacks guidance: %s", body)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate header")
	}
}

func TestAgentAccess_AdminPolicyRejectsViewerKey(t *testing.T) {
	initDB()
	initExtraDB()
	setAgentPolicy(t, agentAdminToken)

	if _, err := CreateUser("policyviewer", "ViewerPass-1", RoleViewer); err != nil {
		t.Fatal(err)
	}
	key := insertTestAPIKey(t, "policy-viewer-key", RoleViewer)

	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	if agentAuthorized(rec, req) {
		t.Fatal("admin-only policy accepted a viewer key")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (credential present but insufficient)", rec.Code)
	}

	adminKey := insertTestAPIKey(t, "policy-admin-key", RoleAdmin)
	req = httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.Header.Set("X-API-Key", adminKey)
	rec = httptest.NewRecorder()
	if !agentAuthorized(rec, req) {
		t.Fatal("admin-only policy rejected an admin key")
	}
}

// The gate must wrap the handler, not replace it.
func TestAgentGateMiddleware_WrapsHandler(t *testing.T) {
	initDB()
	setAgentPolicy(t, agentPublic)
	called := false
	h := agentGateMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ip", nil))
	if !called {
		t.Fatal("handler was not invoked under the public policy")
	}
}

// insertTestAPIKey writes a key row and returns its plaintext secret, mirroring
// what the admin API does (only the hash is stored).
func insertTestAPIKey(t *testing.T, name, scope string) string {
	t.Helper()
	initExtraDB()
	secret := newAPIKeySecret()
	prefix := secret[:12] + "…"
	if _, err := db.Exec(`INSERT INTO api_keys(name, key_hash, prefix, scope, enabled, created_at, expires_at)
		VALUES(?,?,?,?,1,?,?)`,
		name, hashAPIKey(secret), prefix, scope, "2026-01-01T00:00:00Z", ""); err != nil {
		t.Fatalf("insert key: %v", err)
	}
	return secret
}
