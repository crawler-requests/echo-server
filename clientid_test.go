package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The fingerprints below were measured from real clients (curl, wget,
// python-requests, node, java, openssl, Go net/http, Chromium) through this
// server. Keeping them here means a regression in the parser or the table
// shows up as a failing identification, not just a wrong JSON field.

func ch(ja4, ja3hash string, grease bool, alpn ...string) *ClientHelloInfo {
	return &ClientHelloInfo{
		JA4:       ja4,
		JA3Hash:   ja3hash,
		HasGREASE: grease,
		ALPN:      alpn,
		Length:    500,
	}
}

func TestIdentifyClient_MeasuredFingerprints(t *testing.T) {
	cases := []struct {
		name      string
		hello     *ClientHelloInfo
		ua        string
		wantName  string
		wantFam   string
		wantSpoof bool
	}{
		{
			name:     "curl h2",
			hello:    ch("t13i3111h2_e8f1e7e78f70_b26ce05bbdd6", "78f0dc5ac5b19daf131a133cfdee9691", false, "h2", "http/1.1"),
			ua:       "curl/8.5.0",
			wantName: "curl", wantFam: "cli",
		},
		{
			name:     "curl h1 (no h2)",
			hello:    ch("t13i3111h1_e8f1e7e78f70_b26ce05bbdd6", "78f0dc5ac5b19daf131a133cfdee9691", false, "http/1.1"),
			ua:       "curl/8.5.0",
			wantName: "curl", wantFam: "cli",
		},
		{
			// Same OpenSSL crypto stack as curl; only the UA names it.
			name:     "python-requests",
			hello:    ch("t13i3111h1_e8f1e7e78f70_b26ce05bbdd6", "78f0dc5ac5b19daf131a133cfdee9691", false, "http/1.1"),
			ua:       "python-requests/2.31.0",
			wantName: "python-requests", wantFam: "library",
		},
		{
			name:     "wget (GnuTLS)",
			hello:    ch("t13i751000_479067518aa3_fb8d5ffd48c1", "ceae6388daceebc11811eebcebb26df1", false),
			ua:       "Wget/1.21.4",
			wantName: "wget", wantFam: "cli",
		},
		{
			name:     "node",
			hello:    ch("t13i590900_a33745022dd6_1f22a2ca17c4", "6521bd74aad3476cdb3daa827288ec35", false),
			ua:       "",
			wantName: "node", wantFam: "runtime",
		},
		{
			name:     "java 21",
			hello:    ch("t13i311100_1d947a95fc68_7e1102d2036b", "ea0154154790b24e85b5cc9676622c9c", false),
			ua:       "Java/21.0.12",
			wantName: "Java", wantFam: "runtime",
		},
		{
			name:     "openssl s_client",
			hello:    ch("t13d311000_e8f1e7e78f70_1f22a2ca17c4", "a3afc2c46ba4a7d7fbe1cfb7a3031c2f", false),
			ua:       "",
			wantName: "openssl", wantFam: "cli",
		},
		{
			name:     "go net/http (post-quantum key share)",
			hello:    ch("t13d131100_f57a46bbacb6_ab7e3b40a677", "9b7dcdf3f997f1fb7b4409c94cb7ef36", false),
			ua:       "Go-http-client/1.1",
			wantName: "Go net/http", wantFam: "runtime",
		},
		{
			name:     "chromium headless",
			hello:    ch("t13i1516h2_8daaf6152771_cb7bf5808d99", "", true, "h2", "http/1.1"),
			ua:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36",
			wantName: "HeadlessChrome", wantFam: "browser",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := identifyClient(c.hello, c.ua)
			if got == nil {
				t.Fatalf("identifyClient returned nil for %s", c.name)
			}
			if got.Name != c.wantName {
				t.Errorf("name = %q, want %q (evidence %v)", got.Name, c.wantName, got.Matches)
			}
			if got.Family != c.wantFam {
				t.Errorf("family = %q, want %q", got.Family, c.wantFam)
			}
			if got.Spoofed != c.wantSpoof {
				t.Errorf("spoofed = %v, want %v (notes %v)", got.Spoofed, c.wantSpoof, got.Notes)
			}
			if got.Confidence <= 0 || got.Confidence > 1 {
				t.Errorf("confidence = %v, want 0<c<=1", got.Confidence)
			}
		})
	}
}

// "Go-http-client/1.1" carries the HTTP version, not the Go release; the
// reported version must come from the TLS fingerprint instead.
func TestIdentifyClient_GoVersionFromTLS(t *testing.T) {
	hello := ch("t13d131100_f57a46bbacb6_ab7e3b40a677", "9b7dcdf3f997f1fb7b4409c94cb7ef36", false)
	got := identifyClient(hello, "Go-http-client/1.1")
	if got == nil {
		t.Fatal("identifyClient returned nil")
	}
	if got.Version != "1.24+" {
		t.Errorf("version = %q, want the TLS-derived %q (UA only says HTTP/1.1)", got.Version, "1.24+")
	}
}

// TestIdentifyClient_SpoofedChromeUA is the core crawler-debugging case: a
// scraper sends a Chrome User-Agent but its TLS handshake is Go's.
func TestIdentifyClient_SpoofedChromeUA(t *testing.T) {
	goHello := ch("t13d131100_f57a46bbacb6_ab7e3b40a677", "9b7dcdf3f997f1fb7b4409c94cb7ef36", false, "h2", "http/1.1")
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

	got := identifyClient(goHello, ua)
	if got == nil {
		t.Fatal("identifyClient returned nil")
	}
	if !got.Spoofed {
		t.Errorf("expected spoofed=true: UA claims Chrome but TLS is Go (got %+v)", got)
	}
	if got.Name != "Go net/http" || got.Family != "runtime" {
		t.Errorf("spoofed request must be identified by TLS: got name=%q family=%q", got.Name, got.Family)
	}
	if len(got.Notes) == 0 {
		t.Errorf("spoofed request must carry an explanatory note")
	}
}

// Reverse direction: TLS looks like a browser but the UA claims a script.
func TestIdentifyClient_BrowserTLSWithScriptUA(t *testing.T) {
	chromeHello := ch("t13i1516h2_8daaf6152771_cb7bf5808d99", "", true, "h2", "http/1.1")
	got := identifyClient(chromeHello, "python-requests/2.31.0")
	if got == nil {
		t.Fatal("identifyClient returned nil")
	}
	if !got.Spoofed {
		t.Errorf("browser TLS + python UA must be flagged spoofed: %+v", got)
	}
}

// A GREASE-bearing hello with no table hit is still recognized as a browser,
// and the UA names it (this is how real Firefox is handled: browser-family TLS
// + "Firefox/…" UA).
func TestIdentifyClient_UnknownBrowserUsesUA(t *testing.T) {
	ff := ch("t13i1312h2_8daaf6152771_deadbeef1234", "", true, "h2", "http/1.1")
	got := identifyClient(ff, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0")
	if got == nil {
		t.Fatal("identifyClient returned nil")
	}
	if got.Name != "Firefox" || got.Family != "browser" {
		t.Errorf("want Firefox/browser, got %q/%q", got.Name, got.Family)
	}
	if got.Spoofed {
		t.Errorf("browser TLS + browser UA must not be spoofed: %+v", got)
	}
}

func TestIdentifyClient_NoSignals(t *testing.T) {
	if got := identifyClient(&ClientHelloInfo{}, ""); got != nil {
		t.Errorf("no TLS match and no UA must yield nil, got %+v", got)
	}
	if got := identifyClient(nil, ""); got != nil {
		t.Errorf("nil hello and no UA must yield nil, got %+v", got)
	}
}

func TestParseUserAgent(t *testing.T) {
	cases := []struct{ ua, name, family, version string }{
		{"curl/8.5.0", "curl", "cli", "8.5.0"},
		{"Wget/1.21.4", "wget", "cli", "1.21.4"},
		{"python-requests/2.31.0", "python-requests", "library", "2.31.0"},
		{"aiohttp/3.9.1", "aiohttp", "library", "3.9.1"},
		{"httpx/0.27.0", "httpx", "library", "0.27.0"},
		{"okhttp/4.12.0", "okhttp", "library", "4.12.0"},
		{"Go-http-client/1.1", "Go net/http", "runtime", ""}, // 1.1 is the HTTP version, not the Go release
		{"Java/21.0.12", "Java", "runtime", "21.0.12"},
		{"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36", "Chrome", "browser", "131.0.0.0"},
		{"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0", "Edge", "browser", "131.0.0.0"},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/156.0.0.0 Safari/537.36", "HeadlessChrome", "browser", "156.0.0.0"},
		{"Mozilla/5.0 (Windows NT 10.0; rv:133.0) Gecko/20100101 Firefox/133.0", "Firefox", "browser", "133.0"},
		{"Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15", "Safari", "browser", "17.0"},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Googlebot", "bot", ""},
	}
	for _, c := range cases {
		got := parseUserAgent(c.ua)
		if got.name != c.name || got.family != c.family || got.version != c.version {
			t.Errorf("parseUserAgent(%q) = {%q %q %q}, want {%q %q %q}",
				c.ua, got.name, got.family, got.version, c.name, c.family, c.version)
		}
	}
	if got := parseUserAgent(""); got.name != "" {
		t.Errorf("empty UA must not match, got %+v", got)
	}
}

func TestFamilyMismatch(t *testing.T) {
	cases := []struct {
		tls, ua string
		want    bool
	}{
		{"browser", "browser", false},
		{"runtime", "runtime", false},
		{"cli", "cli", false},
		{"http_client", "cli", false},
		{"http_client", "library", false},
		{"runtime", "browser", true},
		{"browser", "library", true},
		{"cli", "browser", true},
		{"unknown", "browser", false}, // unknown side gets a pass
		{"runtime", "bot", true},
	}
	for _, c := range cases {
		if got := familyMismatch(c.tls, c.ua); got != c.want {
			t.Errorf("familyMismatch(%q,%q) = %v, want %v", c.tls, c.ua, got, c.want)
		}
	}
}

func TestHeaderSignature_OrderIndependent(t *testing.T) {
	a := http.Header{"User-Agent": {"x"}, "Accept": {"*/*"}, "Sec-Fetch-Mode": {"navigate"}}
	b := http.Header{"Sec-Fetch-Mode": {"navigate"}, "Accept": {"*/*"}, "User-Agent": {"x"}}
	if headerSignature(a) != headerSignature(b) {
		t.Errorf("header signature must not depend on map iteration order")
	}
	c := http.Header{"User-Agent": {"x"}}
	if headerSignature(a) == headerSignature(c) {
		t.Errorf("different header sets must hash differently")
	}
	if len(headerSignature(a)) != 12 {
		t.Errorf("header signature = %q, want 12 hex chars", headerSignature(a))
	}
}

func TestBrowserLikeHeaders(t *testing.T) {
	browser := http.Header{
		"Sec-Ch-Ua": {`"Chromium"`}, "Sec-Fetch-Site": {"none"}, "Sec-Fetch-Mode": {"navigate"},
		"Accept": {"text/html"}, "Accept-Language": {"en"},
	}
	if !browserLikeHeaders(browser) {
		t.Errorf("browser header set must be detected")
	}
	if browserLikeHeaders(http.Header{"User-Agent": {"curl/8"}}) {
		t.Errorf("curl header set must not look browser-like")
	}
}

// The handler path must expose the client block and honour the show_client
// admin toggle.
func TestEchoHandler_ClientIdentification(t *testing.T) {
	withOfflineGeo(t)
	SetConfig("show_client", "true")
	defer SetConfig("show_client", "true")

	// Simulate a connection-bound hello via the legacy fallback global.
	capturedHello = buildClientHello("clientid.example")
	defer func() { capturedHello = nil }()

	newReq := func() *http.Request {
		req := httptest.NewRequest("GET", "/identify", nil)
		req.Header.Set("User-Agent", "curl/8.5.0")
		return req
	}

	rr := httptest.NewRecorder()
	echoHandler(rr, newReq())
	body := rr.Body.String()
	if !strings.Contains(body, `"client"`) || !strings.Contains(body, `"family"`) {
		t.Fatalf("response must contain a client block, got %s", truncateStr(body, 400))
	}

	SetConfig("show_client", "false")
	rr2 := httptest.NewRecorder()
	echoHandler(rr2, newReq())
	if strings.Contains(rr2.Body.String(), `"client"`) {
		t.Errorf("show_client=false must omit the client block")
	}
}
