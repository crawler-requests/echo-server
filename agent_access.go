package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Agent access policy.
//
// The MCP tools and the fast /ip path are built for machines, but "who may call
// them" must be an operator decision, not something baked into the binary. Three
// levels, set by the admin in 访问控制:
//
//	public       — anyone who can reach the port. Right for an internal network
//	               where the whole point is a scratch endpoint.
//	token        — a valid JWT or API key (any scope). The default: it matches
//	               require_token's spirit without forcing an admin key for a
//	               read-only lookup.
//	admin_token  — an admin-scoped credential only. Right when even reading the
//	               query log or issuing reset tokens must be audited.
//
// The policy is separate from `require_token`, which governs the human-facing
// /echo surface. An operator can expose /echo publicly but lock the agent
// surface down, or the reverse.
const (
	agentPublic     = "public"
	agentToken      = "token"
	agentAdminToken = "admin_token"
)

// agentAccess is the effective policy (defaults to token).
func agentAccess() string {
	switch v := strings.ToLower(strings.TrimSpace(GetConfig("agent_access"))); v {
	case agentPublic, agentToken, agentAdminToken:
		return v
	}
	// Lite mode has no database and no accounts, so there is no credential to
	// check: refuse to silently allow everything, and refuse to break a fresh
	// install that has not configured a policy yet. Public is the only
	// meaningful answer there.
	if liteMode {
		return agentPublic
	}
	return agentToken
}

// agentAuthorized reports whether the request carries enough credential for the
// current policy, and writes the refusal when it does not.
func agentAuthorized(w http.ResponseWriter, r *http.Request) bool {
	switch agentAccess() {
	case agentPublic:
		return true
	case agentAdminToken:
		if u, ok := authenticatedUser(r); ok && u.Role == RoleAdmin {
			return true
		}
		writeAgentDenied(w, r, "this deployment requires an admin credential for agent tools")
		return false
	default: // agentToken
		if _, ok := authenticatedUser(r); ok {
			return true
		}
		writeAgentDenied(w, r, "this deployment requires a credential for agent tools")
		return false
	}
}

// writeAgentDenied returns 401 or 403 with instructions the caller (often an
// agent reading the response) can act on, plus WWW-Authenticate so a client
// knows which scheme to send.
func writeAgentDenied(w http.ResponseWriter, r *http.Request, message string) {
	hasCred := r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != ""
	status := http.StatusUnauthorized
	if hasCred {
		status = http.StatusForbidden // credential present but not sufficient
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="echo-server"`)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	writeJSONBody(w, map[string]any{
		"error":   message,
		"policy":  agentAccess(),
		"hint":    "Send Authorization: Bearer <JWT> or X-API-Key: <key>. Create a key under 安全与防护; the admin can relax this in 访问控制 → Agent access.",
		"console": "/ui/access",
	})
}

// writeJSONBody writes JSON without re-setting the status (the caller already
// called WriteHeader).
func writeJSONBody(w http.ResponseWriter, v any) {
	_, _ = w.Write(mustJSON(v))
}

// agentGateMiddleware wraps a handler with the agent policy.
func agentGateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !agentAuthorized(w, r) {
			return
		}
		next(w, r)
	}
}

// mustJSON marshals a small value for an already-written response; a failure
// here is impossible for the map literals used above.
func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// effectiveAgentAccess is the value the console should display: the stored
// setting when present, otherwise the policy that will actually be enforced.
func effectiveAgentAccess() string {
	if v := strings.ToLower(strings.TrimSpace(GetConfig("agent_access"))); v != "" {
		return v
	}
	return agentAccess()
}
