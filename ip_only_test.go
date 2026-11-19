package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIPOnlyHandler_Formats(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	rec := httptest.NewRecorder()
	ipOnlyHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"ip":"203.0.113.7"}` {
		t.Fatalf("body = %q", got)
	}
	// The IP is per-connection; it must never be cached.
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control = %q", rec.Header().Get("Cache-Control"))
	}

	// text format: the bare address, newline-terminated (curl-friendly).
	req = httptest.NewRequest(http.MethodGet, "/ip?format=text", nil)
	req.RemoteAddr = "198.51.100.3:1"
	rec = httptest.NewRecorder()
	ipOnlyHandler(rec, req)
	if got := rec.Body.String(); got != "198.51.100.3\n" {
		t.Fatalf("text body = %q", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("text content-type = %q", ct)
	}
}

func TestIPOnlyHandler_HonorsForwardingHeaders(t *testing.T) {
	cases := map[string]string{
		"X-Forwarded-For":  "8.8.8.8, 10.0.0.1",
		"X-Real-IP":        "1.1.1.1",
		"CF-Connecting-IP": "9.9.9.9",
	}
	for header, value := range cases {
		req := httptest.NewRequest(http.MethodGet, "/ip", nil)
		req.RemoteAddr = "127.0.0.1:1"
		req.Header.Set(header, value)
		rec := httptest.NewRecorder()
		ipOnlyHandler(rec, req)
		var doc struct {
			IP string `json:"ip"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s: bad json: %v", header, err)
		}
		want := strings.Split(value, ",")[0]
		if doc.IP != strings.TrimSpace(want) {
			t.Fatalf("%s: ip = %q, want %q", header, doc.IP, want)
		}
	}
}

// The fast path must not touch geolocation, client identification or the
// query log: that is what makes it fast. Assert the counter moves but the
// log does not.
func TestIPOnlyHandler_BypassesGeoAndLog(t *testing.T) {
	withOfflineGeo(t)
	before := ipOnlyRequests.Load()

	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "203.0.113.99:1234"
	rec := httptest.NewRecorder()
	ipOnlyHandler(rec, req)

	if ipOnlyRequests.Load() != before+1 {
		t.Fatal("fast-path counter did not increment")
	}
	if rec.Body.Len() > 64 {
		t.Fatalf("response unexpectedly large (%d bytes): the fast path must not build a full echo object", rec.Body.Len())
	}
}
