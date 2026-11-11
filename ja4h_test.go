package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The golden string is the FoxIO JA4H test vector
// (zeek/testing/Baseline/tests.ja4h-http: GET to a host with
// Host, User-Agent, Accept, Accept-Language: da, Referer and two cookies),
// recomputed for this server's documented deviation: header names are sorted
// because Go's http.Header cannot preserve wire order. The cookie field and
// value hashes match the reference byte for byte (280f366eaa04 / c2fb0fe53442),
// which is what proves the cookie handling is spec-compliant.
func TestJA4H_ReferenceVector(t *testing.T) {
	h := http.Header{
		"Host":            {"example.com"},
		"User-Agent":      {"curl/8.5.0"},
		"Accept":          {"*/*"},
		"Accept-Language": {"da"},
		"Referer":         {"http://example.com/"},
		"Cookie":          {"yummy_cookie=choco; tasty_cookie=strawberry"},
	}
	got := ja4hFromParts("GET", "HTTP/1.1", h)
	want := "ge11cr04da00_73349af45e10_280f366eaa04_c2fb0fe53442"
	if got != want {
		t.Fatalf("ja4h = %q, want %q", got, want)
	}
}

func TestJA4H_NoCookiesNoReferer(t *testing.T) {
	h := http.Header{"Host": {"x"}, "User-Agent": {"curl/8.5.0"}, "Accept": {"*/*"}}
	got := ja4hFromParts("GET", "HTTP/1.1", h)
	// ge = GET, 11 = HTTP/1.1, n = no cookie, n = no referer, 03 headers, 0000 lang
	if !strings.HasPrefix(got, "ge11nn030000_") {
		t.Fatalf("ja4h = %q, want prefix ge11nn030000_", got)
	}
	parts := strings.Split(got, "_")
	if len(parts) != 4 {
		t.Fatalf("ja4h must have 4 underscore-separated parts, got %d: %q", len(parts), got)
	}
	if parts[2] != zeroHash() || parts[3] != zeroHash() {
		t.Errorf("absent cookies must hash to the 000000000000 marker, got %q/%q", parts[2], parts[3])
	}
	if parts[1] != ja4hHash12("accept,host,user-agent") {
		t.Errorf("header hash must cover the sorted non-cookie/referer names, got %q", parts[1])
	}
}

func TestJA4H_LanguageAndMethodAndVersion(t *testing.T) {
	// Head = method + version + c/n + r/n + 2-digit header count + language.
	// The header count includes Host and Accept-Language, but never Cookie or
	// Referer.
	cases := []struct{ lang, proto, method, wantHead string }{
		{"en-US,en;q=0.9", "HTTP/1.1", "GET", "ge11nn02enus"},
		{"da", "HTTP/1.0", "POST", "po10nn02da00"},
		{"zh-CN", "HTTP/2.0", "HEAD", "he20nn02zhcn"},
		{"", "HTTP/1.1", "DELETE", "de11nn010000"},
	}
	for _, c := range cases {
		h := http.Header{"Host": {"x"}}
		if c.lang != "" {
			h.Set("Accept-Language", c.lang)
		}
		got := ja4hFromParts(c.method, c.proto, h)
		if !strings.HasPrefix(got, c.wantHead) {
			t.Errorf("method=%s proto=%s lang=%q -> %q, want prefix %q",
				c.method, c.proto, c.lang, got, c.wantHead)
		}
	}
	// "en-US" is dash-stripped and lowercased before the 4-char truncation.
	if got := ja4hLanguage("en-US,en;q=0.9"); got != "enus" {
		t.Errorf("ja4hLanguage(en-US,...) = %q, want enus", got)
	}
	if got := ja4hLanguage("da"); got != "da00" {
		t.Errorf("ja4hLanguage(da) = %q, want da00", got)
	}
	if got := ja4hLanguage(""); got != "0000" {
		t.Errorf("ja4hLanguage(\"\") = %q, want 0000", got)
	}
}

func TestJA4H_CookieOrderIndependent(t *testing.T) {
	a := http.Header{"Host": {"x"}, "Cookie": {"b=2; a=1"}}
	b := http.Header{"Host": {"x"}, "Cookie": {"a=1; b=2"}}
	if ja4hFromParts("GET", "HTTP/1.1", a) != ja4hFromParts("GET", "HTTP/1.1", b) {
		t.Errorf("JA4H must not depend on cookie order (the spec sorts fields)")
	}
}

// The echo handler must expose ja4h, and the admin toggle must suppress it.
func TestEchoHandler_JA4H(t *testing.T) {
	withOfflineGeo(t)
	SetConfig("show_ja4h", "true")
	defer SetConfig("show_ja4h", "true")

	req := httptest.NewRequest("GET", "/echo", nil)
	req.Header.Set("User-Agent", "curl/8.5.0")
	rr := httptest.NewRecorder()
	echoHandler(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `"ja4h":"ge11nn`) {
		t.Fatalf("response must carry a ja4h fingerprint, got %s", truncateStr(body, 400))
	}

	SetConfig("show_ja4h", "false")
	rr2 := httptest.NewRecorder()
	echoHandler(rr2, httptest.NewRequest("GET", "/echo", nil))
	if strings.Contains(rr2.Body.String(), `"ja4h"`) {
		t.Errorf("show_ja4h=false must omit ja4h")
	}
}

// A real request through the handler body: the fingerprint reflects the actual
// header set (User-Agent + Accept + Host-as-header are what curl sends).
func TestJA4H_HandlerMatchesHeaderSet(t *testing.T) {
	withOfflineGeo(t)
	req := httptest.NewRequest("POST", "/echo", strings.NewReader("x"))
	req.Header.Set("User-Agent", "curl/8.5.0")
	req.Header.Set("Accept", "*/*")
	want := ja4hFromParts("POST", "HTTP/1.1", req.Header)
	if got := ja4hFingerprint(req); got != want {
		t.Fatalf("ja4hFingerprint = %q, want %q", got, want)
	}
	if !strings.HasPrefix(want, "po11nn02") { // no cookie, no referer, 2 headers
		t.Errorf("unexpected head: %q", want)
	}
}
