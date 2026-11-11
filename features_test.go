package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestMain points SQLite at a throwaway database so tests never touch the
// operator's real ~/.echo-server/echo.db.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "echo-server-test-*")
	if err != nil {
		panic(err)
	}
	os.Setenv("ECHO_SERVER_DB", filepath.Join(dir, "test.db"))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// withOfflineGeo pins IP intel to offline for a test so assertions are
// deterministic and never depend on outbound network calls.
func withOfflineGeo(t *testing.T) {
	t.Helper()
	prevOnline := GetConfig("enable_online_geo")
	prevProvider := GetConfig("geo_provider")
	if err := SetConfig("enable_online_geo", "false"); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	SetConfig("geo_provider", "")
	resetGeoCache()
	t.Cleanup(func() {
		SetConfig("enable_online_geo", prevOnline)
		SetConfig("geo_provider", prevProvider)
		resetGeoCache()
	})
}

func resetGeoCache() {
	geoCache.Lock()
	geoCache.m = map[string]geoCacheEntry{}
	geoCache.order = nil
	geoCache.Unlock()
}

// --- TLS capture -----------------------------------------------------------

func TestHelloConn_CapturesRecordAndPayloadPerConnection(t *testing.T) {
	record := []byte{
		0x16, 0x03, 0x01, 0x00, 0x0a, // handshake record, TLS1.0, length 10
		0x01, 0x00, 0x00, 0x06, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, // ClientHello payload
	}
	server, client := net.Pipe()
	defer server.Close()

	hc := &helloConn{Conn: server}
	go func() {
		client.Write(record)
		client.Close()
	}()

	buf := make([]byte, 4096)
	if _, err := hc.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := hc.HelloRecord(); !bytes.Equal(got, record) {
		t.Errorf("HelloRecord = %x, want %x", got, record)
	}
	if got := hc.HelloPayload(); !bytes.Equal(got, record[5:]) {
		t.Errorf("HelloPayload = %x, want %x", got, record[5:])
	}
}

func TestHelloConn_NonTLSDataCapturesNothing(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	hc := &helloConn{Conn: server}
	go func() {
		client.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		client.Close()
	}()
	buf := make([]byte, 4096)
	hc.Read(buf)
	if hc.HelloPayload() != nil || hc.HelloRecord() != nil {
		t.Errorf("non-TLS bytes must not be captured as a ClientHello")
	}
}

// buildClientHello builds a minimal valid ClientHello handshake message
// (record-header stripped) including a server_name (SNI) extension.
func buildClientHello(sni string) []byte {
	ext := []byte{0, 0}
	listLen := 1 + 2 + len(sni)
	ext[0] = byte(listLen >> 8)
	ext[1] = byte(listLen)
	ext = append(ext, 0, byte(len(sni)>>8), byte(len(sni)))
	ext = append(ext, []byte(sni)...)

	var b bytes.Buffer
	b.Write([]byte{0x01, 0x00, 0x00, 0x00}) // type + placeholder length
	b.Write([]byte{0x03, 0x03})             // version TLS1.2
	b.Write(make([]byte, 32))               // random
	b.Write([]byte{0x00})                   // session id length
	b.Write([]byte{0x00, 0x02, 0x13, 0x01}) // cipher suites (one)
	b.Write([]byte{0x01, 0x00})             // compression methods
	var exts bytes.Buffer
	exts.Write([]byte{0x00, 0x00, 0x00, byte(len(ext))}) // type server_name + length
	exts.Write(ext)
	b.Write([]byte{byte(exts.Len() >> 8), byte(exts.Len())})
	b.Write(exts.Bytes())

	raw := b.Bytes()
	// fix handshake length (3 bytes at offset 1)
	hl := len(raw) - 4
	raw[1] = byte(hl >> 16)
	raw[2] = byte(hl >> 8)
	raw[3] = byte(hl)
	return raw
}

func TestParseClientHelloFields_ExtractsSNIAndCiphers(t *testing.T) {
	raw := buildClientHello("example.com")
	vers, ciphers, exts, sni := parseClientHelloFields(raw)
	if vers != 0x0303 {
		t.Errorf("version = %#x, want 0x0303", vers)
	}
	if len(ciphers) != 1 || ciphers[0] != 0x1301 {
		t.Errorf("cipher suites = %v, want [4865]", ciphers)
	}
	if len(exts) == 0 || exts[0] != 0x0000 {
		t.Errorf("extensions = %v, want leading server_name", exts)
	}
	if sni != "example.com" {
		t.Errorf("sni = %q, want example.com", sni)
	}
}

func TestParseSNI_RejectsMalformed(t *testing.T) {
	if got := parseSNI(nil); got != "" {
		t.Errorf("parseSNI(nil) = %q", got)
	}
	if got := parseSNI([]byte{0, 1, 0, 0, 9, 'a'}); got != "" {
		t.Errorf("truncated SNI should be rejected, got %q", got)
	}
}

func TestPopulateClientHelloWith_RawHexMatchesBase64(t *testing.T) {
	raw := buildClientHello("hex.example")
	info := &ClientHelloInfo{}
	populateClientHelloWith(info, raw)

	if info.Length != len(raw) {
		t.Errorf("Length = %d, want %d", info.Length, len(raw))
	}
	if len(info.RawHex) != len(raw)*2 {
		t.Errorf("RawHex length = %d, want %d", len(info.RawHex), len(raw)*2)
	}
	decoded, err := base64.StdEncoding.DecodeString(info.Raw)
	if err != nil {
		t.Fatalf("raw_base64 not valid base64: %v", err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Errorf("raw_base64 does not round-trip the ClientHello")
	}
	if info.JA3 == "" || info.JA3Hash == "" {
		t.Errorf("JA3 must be populated")
	}
	if info.SNI != "hex.example" {
		t.Errorf("SNI = %q", info.SNI)
	}
}

// --- response format / field filtering -------------------------------------

func sampleResponse() EchoResponse {
	return EchoResponse{
		Timestamp:  "2026-11-04T00:00:00Z",
		Method:     "GET",
		Path:       "/echo",
		BodyLength: 0,
		Headers:    map[string][]string{"User-Agent": {"test"}},
		IP: &IPInfo{
			IP:             "8.8.8.8",
			Country:        "United States",
			CountryCode:    "US",
			City:           "Mountain View",
			Region:         "California",
			Latitude:       37.4,
			Longitude:      -122.1,
			ConnectionType: "datacenter",
			GeoSource:      "ipwhois",
		},
		ClientHello: &ClientHelloInfo{Length: 10, SNI: "example.com", JA3: "771,1,0", JA3Hash: "abc"},
	}
}

func TestSerializeEcho_JSONFieldFilter(t *testing.T) {
	data, ct, err := serializeEcho(sampleResponse(), "json", "ip.country,ip.connection_type")
	if err != nil {
		t.Fatalf("serializeEcho: %v", err)
	}
	if !strings.Contains(ct, "application/json") {
		t.Errorf("content type = %q", ct)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := m["method"]; ok {
		t.Errorf("method should be filtered out: %v", m)
	}
	ip, ok := m["ip"].(map[string]any)
	if !ok {
		t.Fatalf("ip object missing: %v", m)
	}
	if ip["country"] != "United States" || ip["connection_type"] != "datacenter" {
		t.Errorf("requested ip fields missing: %v", ip)
	}
	if len(ip) != 2 {
		t.Errorf("only the requested ip fields should remain, got %v", ip)
	}
}

func TestSerializeEcho_TextFormatFlattens(t *testing.T) {
	data, ct, err := serializeEcho(sampleResponse(), "text", "")
	if err != nil {
		t.Fatalf("serializeEcho: %v", err)
	}
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("content type = %q", ct)
	}
	text := string(data)
	for _, want := range []string{
		"method=GET\n",
		"ip.country=United States\n",
		"ip.latitude=37.4\n",
		"client_hello.sni=example.com\n",
		`headers.User-Agent=["test"]`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text output missing %q:\n%s", want, text)
		}
	}
}

func TestSerializeEcho_TextWithFields(t *testing.T) {
	data, _, err := serializeEcho(sampleResponse(), "text", "ip.city,ip.latitude")
	if err != nil {
		t.Fatalf("serializeEcho: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "ip.city=Mountain View") {
		t.Errorf("missing ip.city:\n%s", text)
	}
	if strings.Contains(text, "ip.region") || strings.Contains(text, "method=") {
		t.Errorf("filtered-out fields leaked:\n%s", text)
	}
}

func TestFilterFieldsMap_WholeObjectThenSubField(t *testing.T) {
	m := map[string]any{
		"ip":     map[string]any{"country": "US", "city": "X"},
		"method": "GET",
	}
	got := filterFieldsMap(m, []string{"ip", "ip.country"})
	ip := got["ip"].(map[string]any)
	if len(ip) != 2 {
		t.Errorf("whole 'ip' should include all children, got %v", ip)
	}
	if _, ok := got["method"]; ok {
		t.Errorf("method should not be included")
	}

	got2 := filterFieldsMap(m, []string{"nope", "ip.missing"})
	if len(got2) != 0 {
		t.Errorf("unknown fields must be ignored, got %v", got2)
	}
}

// --- handler wiring ---------------------------------------------------------

func TestEchoHandler_TextFormatAndFields(t *testing.T) {
	withOfflineGeo(t)
	req := httptest.NewRequest(http.MethodGet, "/echo?format=text&fields=ip.ip,ip.connection_type", nil)
	req.RemoteAddr = "8.8.8.8:4000"
	rr := httptest.NewRecorder()
	echoHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("content type = %q, want text/plain", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "ip.ip=8.8.8.8") || !strings.Contains(body, "ip.connection_type=datacenter") {
		t.Errorf("expected ip fields in text output, got:\n%s", body)
	}
	if strings.Contains(body, "method=") || strings.Contains(body, "timestamp=") {
		t.Errorf("only requested fields should appear, got:\n%s", body)
	}
}

func TestEchoHandler_HeaderChannelControls(t *testing.T) {
	withOfflineGeo(t)
	req := httptest.NewRequest(http.MethodGet, "/echo", nil)
	req.RemoteAddr = "8.8.8.8:4000"
	req.Header.Set("X-Echo-Format", "text")
	req.Header.Set("X-Echo-Fields", "ip.connection_type")
	rr := httptest.NewRecorder()
	echoHandler(rr, req)

	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("X-Echo-Format=text must switch to text/plain, got %q", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "ip.connection_type=datacenter") {
		t.Errorf("X-Echo-Fields not applied, got:\n%s", body)
	}
}

func TestEchoHandler_DefaultIsFullJSON(t *testing.T) {
	withOfflineGeo(t)
	req := httptest.NewRequest(http.MethodGet, "/echo", nil)
	req.RemoteAddr = "8.8.8.8:4000"
	rr := httptest.NewRecorder()
	echoHandler(rr, req)

	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("default content type = %q", ct)
	}
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, k := range []string{"timestamp", "method", "scheme", "host", "remote_addr", "path", "http_version", "headers", "body", "body_length", "client_hello", "ip"} {
		if _, ok := m[k]; !ok {
			t.Errorf("default response missing %q", k)
		}
	}
}

// TestConcurrentEchoHandlers_NoCrossTalk floods the handler (which shares the
// geo cache and config reads) and asserts every response carries its own IP.
// Run with -race to catch unsynchronized cache/global access.
func TestConcurrentEchoHandlers_NoCrossTalk(t *testing.T) {
	withOfflineGeo(t)
	want := map[string]string{
		"8.8.8.8":         "datacenter",
		"1.0.64.97":       "residential_proxy",
		"52.1.2.3":        "datacenter",
		"114.114.114.114": "unknown",
	}
	ips := []string{"8.8.8.8", "1.0.64.97", "52.1.2.3", "114.114.114.114"}
	errs := make(chan string, 400)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		ip := ips[i%len(ips)]
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/echo?fields=ip.ip,ip.connection_type", nil)
			req.Header.Set("X-Forwarded-For", ip)
			req.RemoteAddr = "127.0.0.1:1"
			rr := httptest.NewRecorder()
			echoHandler(rr, req)
			var m map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
				errs <- "invalid JSON: " + err.Error()
				return
			}
			got, ok := m["ip"].(map[string]any)
			if !ok {
				errs <- "missing ip object for " + ip
				return
			}
			if got["ip"] != ip {
				errs <- "ip = " + got["ip"].(string) + ", want " + ip
			}
			if got["connection_type"] != want[ip] {
				errs <- "connection_type for " + ip + " = " + got["connection_type"].(string) + ", want " + want[ip]
			}
		}(ip)
	}
	wg.Wait()
	close(errs)
	n := 0
	for e := range errs {
		if n < 5 {
			t.Error(e)
		}
		n++
	}
	if n > 5 {
		t.Errorf("... and %d more mismatches", n-5)
	}
}

func TestExtractClientIP_IPv6(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[2001:db8::1]:443"
	if got := extractClientIP(req); got != "2001:db8::1" {
		t.Errorf("IPv6 client IP = %q, want 2001:db8::1", got)
	}
	req.RemoteAddr = "[::1]"
	if got := extractClientIP(req); got != "[::1]" {
		t.Errorf("bare IPv6 literal = %q", got)
	}
}

func TestRootHandler_RequireToken(t *testing.T) {
	withOfflineGeo(t)
	prevReq := GetConfig("require_token")
	prevTok := GetConfig("api_token")
	SetConfig("require_token", "true")
	SetConfig("api_token", "s3cret-token")
	t.Cleanup(func() {
		SetConfig("require_token", prevReq)
		SetConfig("api_token", prevTok)
	})

	// Missing token -> 401
	req := httptest.NewRequest(http.MethodGet, "/echo", nil)
	req.RemoteAddr = "127.0.0.1:5000"
	rr := httptest.NewRecorder()
	rootHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("without token: status = %d, want 401", rr.Code)
	}

	// Valid token -> 200
	req2 := httptest.NewRequest(http.MethodGet, "/echo", nil)
	req2.RemoteAddr = "127.0.0.1:5000"
	req2.Header.Set("X-API-Token", "s3cret-token")
	rr2 := httptest.NewRecorder()
	rootHandler(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Errorf("with token: status = %d, want 200 (body=%s)", rr2.Code, rr2.Body.String())
	}
}

// --- IP intel ---------------------------------------------------------------

func TestFetchIPInfo_OfflineIsHonest(t *testing.T) {
	withOfflineGeo(t)

	dc := fetchIPInfo("8.8.8.8")
	if dc == nil || dc.ConnectionType != "datacenter" {
		t.Errorf("8.8.8.8 offline connection_type = %v, want datacenter", dc)
	}
	if dc.GeoSource != "local" {
		t.Errorf("offline geo_source = %q, want local", dc.GeoSource)
	}
	// Offline must not fabricate geolocation (the old code claimed CN/Shanghai).
	if dc.Country != "" || dc.City != "" {
		t.Errorf("offline must not invent geolocation, got country=%q city=%q", dc.Country, dc.City)
	}

	rp := fetchIPInfo("1.0.64.97")
	if rp == nil || rp.ConnectionType != "residential_proxy" {
		t.Errorf("1.0.64.97 offline connection_type = %v, want residential_proxy", rp)
	}
}

func TestFetchIPInfo_PrivateNeverNetworks(t *testing.T) {
	// Even with online enabled, private/loopback must be local-only.
	prev := GetConfig("enable_online_geo")
	SetConfig("enable_online_geo", "true")
	t.Cleanup(func() { SetConfig("enable_online_geo", prev) })

	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.5", "::1"} {
		info := fetchIPInfo(ip)
		if info == nil || info.GeoSource != "local" {
			t.Errorf("%s should be classified locally without a network lookup, got %+v", ip, info)
		}
	}
}

func TestLookupIPWhoIs_Online(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in -short mode")
	}
	g, err := lookupIPWhoIs("8.8.8.8")
	if err != nil {
		t.Skipf("ipwho.is unavailable from this host: %v", err)
	}
	if g.Country == "" || g.CountryCode == "" || g.City == "" {
		t.Errorf("ipwho.is geolocation incomplete: %+v", g)
	}
	if g.Lat == 0 && g.Lon == 0 {
		t.Errorf("ipwho.is must return latitude/longitude, got %+v", g)
	}
	if g.ASN == "" {
		t.Errorf("ipwho.is must return ASN, got %+v", g)
	}
}

func TestFetchIPInfo_OnlineEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in -short mode")
	}
	prev := GetConfig("enable_online_geo")
	SetConfig("enable_online_geo", "true")
	SetConfig("geo_provider", "")
	t.Cleanup(func() {
		SetConfig("enable_online_geo", prev)
		SetConfig("geo_provider", "")
		resetGeoCache()
	})
	resetGeoCache()

	info := fetchIPInfo("8.8.8.8")
	if info == nil {
		t.Fatal("nil info")
	}
	if info.ConnectionType != "datacenter" {
		t.Errorf("connection_type = %q, want datacenter", info.ConnectionType)
	}
	if info.GeoSource == "local" {
		t.Skip("no provider reachable from this host")
	}
	if info.Country == "" || info.Latitude == 0 {
		t.Errorf("online lookup should populate country and latitude, got %+v", info)
	}
	// Cached second call must return identical data without another lookup.
	again := fetchIPInfo("8.8.8.8")
	if again.Country != info.Country || again.Latitude != info.Latitude {
		t.Errorf("cached result drifted: %+v vs %+v", again, info)
	}
}

func TestGeoProviderConfigOverride(t *testing.T) {
	prevOnline := GetConfig("enable_online_geo")
	prevProvider := GetConfig("geo_provider")
	t.Cleanup(func() {
		SetConfig("enable_online_geo", prevOnline)
		SetConfig("geo_provider", prevProvider)
	})

	SetConfig("enable_online_geo", "false")
	if got := geoProvider(); got != "offline" {
		t.Errorf("enable_online_geo=false -> provider %q, want offline", got)
	}
	SetConfig("enable_online_geo", "true")
	SetConfig("geo_provider", "ipapi")
	if got := geoProvider(); got != "ipapi" {
		t.Errorf("geo_provider=ipapi -> %q", got)
	}
	SetConfig("geo_provider", "bogus")
	if got := geoProvider(); got != "auto" {
		t.Errorf("bogus provider should fall back to auto, got %q", got)
	}
}
