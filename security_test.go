package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// setConfigForTest writes a config key and restores it afterwards, so tests do
// not leak state into each other through the shared SQLite config table.
func setConfigForTest(t *testing.T, key, value string) {
	t.Helper()
	prev := GetConfig(key)
	if err := SetConfig(key, value); err != nil {
		t.Fatalf("set %s: %v", key, err)
	}
	t.Cleanup(func() { _ = SetConfig(key, prev) })
}

func TestParseIPRulesAndCheckIP(t *testing.T) {
	setConfigForTest(t, "ip_allowlist", "")
	setConfigForTest(t, "ip_denylist", "203.0.113.9, 198.51.100.0/24\n# comment\n10.0.0.1")
	setConfigForTest(t, "ip_allowlist", "")

	if ok, _ := checkIP("203.0.113.9"); ok {
		t.Fatal("exact denied IP was allowed")
	}
	if ok, _ := checkIP("198.51.100.42"); ok {
		t.Fatal("CIDR denied IP was allowed")
	}
	if ok, _ := checkIP("10.0.0.1"); ok {
		t.Fatal("single-host denied IP was allowed")
	}
	if ok, _ := checkIP("8.8.8.8"); !ok {
		t.Fatal("unlisted IP was rejected")
	}
	if ok, _ := checkIP("not-an-ip"); !ok {
		t.Fatal("unparseable IP should not be rejected")
	}

	setConfigForTest(t, "ip_denylist", "")
	setConfigForTest(t, "ip_allowlist", "10.0.0.0/8, 192.168.1.83")
	if ok, _ := checkIP("8.8.8.8"); ok {
		t.Fatal("IP outside a non-empty allowlist was allowed")
	}
	if ok, _ := checkIP("10.20.30.40"); !ok {
		t.Fatal("IP inside the allowlist was rejected")
	}
	if ok, _ := checkIP("192.168.1.83"); !ok {
		t.Fatal("exact allowlisted IP was rejected")
	}
}

func TestAllowRate(t *testing.T) {
	setConfigForTest(t, "rate_limit_per_min", "2")
	ip := "192.0.2.201"
	if !allowRate(ip) || !allowRate(ip) {
		t.Fatal("first two requests should pass")
	}
	if allowRate(ip) {
		t.Fatal("third request exceeded the budget but was allowed")
	}
	if !allowRate("192.0.2.202") {
		t.Fatal("a different IP should have its own bucket")
	}
	setConfigForTest(t, "rate_limit_per_min", "0")
	if !allowRate(ip) || !allowRate(ip) || !allowRate(ip) {
		t.Fatal("limit 0 should disable the limiter")
	}
}

func TestIsEchoTraffic(t *testing.T) {
	cases := map[string]bool{
		"/":            true,
		"/echo":        true,
		"/anything":    true,
		"/api":         false,
		"/api/config":  false,
		"/ui":          false,
		"/ui/logs":     false,
		"/health":      false,
		"/metrics":     false,
		"/favicon.ico": false,
	}
	for path, want := range cases {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if got := isEchoTraffic(r); got != want {
			t.Errorf("isEchoTraffic(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestSecurityMiddlewareIPRulesExemptConsole(t *testing.T) {
	setConfigForTest(t, "ip_denylist", "203.0.113.9")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := securityMiddleware(next)

	echoReq := httptest.NewRequest(http.MethodGet, "/echo", nil)
	echoReq.RemoteAddr = "203.0.113.9:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, echoReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied echo traffic status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("baseline security header missing: %q", got)
	}

	consoleReq := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	consoleReq.RemoteAddr = "203.0.113.9:5555"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, consoleReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("console request from a denied IP status = %d, want 200", rec.Code)
	}
}

func TestSecurityMiddlewareMaintenanceExemptsConsole(t *testing.T) {
	setConfigForTest(t, "maintenance_mode", "true")
	setConfigForTest(t, "maintenance_message", "planned upgrade")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := securityMiddleware(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/echo", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("echo during maintenance status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "planned upgrade") {
		t.Fatalf("maintenance message missing: %q", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("console during maintenance status = %d, want 200", rec.Code)
	}
}

func TestSecurityMiddlewareBodyLimit(t *testing.T) {
	setConfigForTest(t, "body_limit_kb", "1")
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	h := securityMiddleware(next)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(strings.Repeat("a", 4096))))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader("small")))
	if rec.Code != http.StatusOK {
		t.Fatalf("in-limit body status = %d, want 200", rec.Code)
	}
}

func TestCORSConfiguredOrigins(t *testing.T) {
	setConfigForTest(t, "cors_origins", "https://a.example, https://b.example")
	h := securityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	req := httptest.NewRequest(http.MethodGet, "/echo", nil)
	req.Header.Set("Origin", "https://a.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://a.example" {
		t.Fatalf("allowed origin header = %q", got)
	}

	req = httptest.NewRequest(http.MethodOptions, "/echo", nil)
	req.Header.Set("Origin", "https://b.example")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/echo", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unlisted origin was echoed: %q", got)
	}
}
