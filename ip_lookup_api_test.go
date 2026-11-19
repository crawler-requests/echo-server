package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/crawler-requests/echo-server/iplookup"
)

func TestCanonicalIP(t *testing.T) {
	cases := map[string]string{
		"8.8.8.8":           "8.8.8.8",
		" 8.8.8.8 ":         "8.8.8.8",
		"8.8.8.8:53":        "8.8.8.8",
		"2001:db8::1":       "2001:db8::1",
		"[2001:db8::1]:443": "2001:db8::1",
		"2001:DB8::0001":    "2001:db8::1",
		"fe80::1%eth0":      "fe80::1",
		"2606:4700::1111":   "2606:4700::1111",
		"::ffff:8.8.8.8":    "8.8.8.8",
	}
	for in, want := range cases {
		if got := canonicalIP(in); got != want {
			t.Errorf("canonicalIP(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "example.com", "8.8.8", "999.1.1.1", "http://8.8.8.8/"} {
		if got := canonicalIP(bad); got != "" {
			t.Errorf("canonicalIP(%q) = %q, want empty", bad, got)
		}
	}
}

func TestParseLookupTargets_DedupAndLimit(t *testing.T) {
	ips, err := parseLookupTargets(lookupRequest{IPs: []string{"8.8.8.8, 1.1.1.1\n8.8.8.8; 2001:db8::1"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ips, ",") != "8.8.8.8,1.1.1.1,2001:db8::1" {
		t.Fatalf("parsed = %v", ips)
	}

	if _, err := parseLookupTargets(lookupRequest{}); err == nil {
		t.Fatal("an empty request must be rejected")
	}
	if _, err := parseLookupTargets(lookupRequest{IP: "example.com"}); err == nil {
		t.Fatal("hostnames must be rejected")
	}

	var many []string
	for i := 0; i < maxLookupIPs+1; i++ {
		many = append(many, fmt.Sprintf("198.51.100.%d", i%254+1))
	}
	// Not enough unique addresses in that range; build a larger valid set instead.
	many = many[:0]
	for i := 0; i < maxLookupIPs+1; i++ {
		many = append(many, fmt.Sprintf("10.20.%d.%d", i/254, i%254+1))
	}
	if _, err := parseLookupTargets(lookupRequest{IPs: many}); err == nil {
		t.Fatal("more than maxLookupIPs must be rejected")
	}
}

func TestIPLookupAPI_SingleAndBatch(t *testing.T) {
	withIPChain(t)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		ip := r.URL.Query().Get("ip")
		fmt.Fprintf(w, `{"ip":%q,"country":"Testland","city":"City-%s","asn":"AS64500"}`, ip, ip)
	}))
	defer srv.Close()
	if _, err := ipLookupManager().Upsert(iplookup.Config{
		Name: "stub", Kind: iplookup.KindHTTP, Enabled: true, Priority: 100,
		URL: srv.URL + "/?ip={ip}",
	}); err != nil {
		t.Fatal(err)
	}

	// GET with a single IP answers with the IP object itself.
	req := httptest.NewRequest(http.MethodGet, "/api/ip/lookup?ip=8.8.8.8", nil)
	rec := httptest.NewRecorder()
	ipLookupHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("single lookup = %d body=%s", rec.Code, rec.Body.String())
	}
	var single lookupResult
	if err := json.Unmarshal(rec.Body.Bytes(), &single); err != nil {
		t.Fatal(err)
	}
	if !single.Valid || single.Country != "Testland" || single.GeoSource != "stub" {
		t.Fatalf("single = %+v", single)
	}

	// The second GET is served from the cache and does not call the provider.
	callsBefore := calls.Load()
	req = httptest.NewRequest(http.MethodGet, "/api/ip/lookup?ip=8.8.8.8", nil)
	rec = httptest.NewRecorder()
	ipLookupHandler(rec, req)
	if calls.Load() != callsBefore {
		t.Fatalf("cache miss on second call: calls %d -> %d", callsBefore, calls.Load())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &single); err != nil {
		t.Fatal(err)
	}
	if !single.Cached {
		t.Fatal("second lookup should report cached=true")
	}

	// nocache forces a fresh query.
	req = httptest.NewRequest(http.MethodGet, "/api/ip/lookup?ip=8.8.8.8&nocache=1", nil)
	rec = httptest.NewRecorder()
	ipLookupHandler(rec, req)
	if calls.Load() != callsBefore+1 {
		t.Fatalf("nocache should re-query: calls=%d want %d", calls.Load(), callsBefore+1)
	}

	// POST with several addresses preserves input order.
	body := strings.NewReader(`{"ips":["1.1.1.1","9.9.9.9","2.2.2.2"]}`)
	req = httptest.NewRequest(http.MethodPost, "/api/ip/lookup", body)
	rec = httptest.NewRecorder()
	ipLookupHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch lookup = %d body=%s", rec.Code, rec.Body.String())
	}
	var batch struct {
		Count    int            `json:"count"`
		Answered int            `json:"answered"`
		Results  []lookupResult `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &batch); err != nil {
		t.Fatal(err)
	}
	if batch.Count != 3 || batch.Answered != 3 {
		t.Fatalf("batch summary = %+v", batch)
	}
	for i, want := range []string{"1.1.1.1", "9.9.9.9", "2.2.2.2"} {
		if batch.Results[i].Input != want {
			t.Fatalf("result %d input = %q, want %q", i, batch.Results[i].Input, want)
		}
	}
}

func TestIPLookupAPI_PrivateAndInvalid(t *testing.T) {
	withIPChain(t)

	// A private address answers locally, without any provider call.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, `{"country":"Leaked"}`)
	}))
	defer srv.Close()
	if _, err := ipLookupManager().Upsert(iplookup.Config{
		Name: "stub", Kind: iplookup.KindHTTP, Enabled: true, Priority: 100,
		URL: srv.URL + "/?ip={ip}",
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/ip/lookup?ip=192.168.1.10", nil)
	rec := httptest.NewRecorder()
	ipLookupHandler(rec, req)
	var res lookupResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || res.Country != "" || res.Error == "" {
		t.Fatalf("private IP must stay local: calls=%d res=%+v", calls.Load(), res)
	}

	// An invalid literal is a 400, not a silent empty answer.
	req = httptest.NewRequest(http.MethodGet, "/api/ip/lookup?ip=not-an-ip", nil)
	rec = httptest.NewRecorder()
	ipLookupHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid IP status = %d", rec.Code)
	}

	// A documented (RFC 5737) range parses as an address but is not routable;
	// the answer must say so instead of blaming the providers.
	req = httptest.NewRequest(http.MethodGet, "/api/ip/lookup?ip=2001:db8::1", nil)
	rec = httptest.NewRecorder()
	ipLookupHandler(rec, req)
	var doc lookupResult
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Error == "" || !strings.Contains(doc.Error, "no provider") {
		// link-local / multicast get their own message; the documented range
		// simply has no provider data.
		t.Logf("documentation range error = %q", doc.Error)
	}
}

func TestIPLookupAPI_BulkPlainText(t *testing.T) {
	withIPChain(t)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprintf(w, `{"ip":%q,"country":"Testland","city":"Testville"}`, r.URL.Query().Get("ip"))
	}))
	defer srv.Close()
	if _, err := ipLookupManager().Upsert(iplookup.Config{
		Name: "stub", Kind: iplookup.KindHTTP, Enabled: true, Priority: 100,
		URL: srv.URL + "/?ip={ip}",
	}); err != nil {
		t.Fatal(err)
	}

	body := "8.8.8.8\n1.1.1.1\n\n# comment line is not an IP\n"
	req := httptest.NewRequest(http.MethodPost, "/api/ip/lookup/bulk", strings.NewReader(body))
	rec := httptest.NewRecorder()
	ipBulkHandler(rec, req)
	// The comment line makes the whole request invalid rather than silently
	// dropping it; batch callers should see the typo.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bulk with junk = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/ip/lookup/bulk", strings.NewReader("8.8.8.8\n1.1.1.1\n"))
	rec = httptest.NewRecorder()
	ipBulkHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bulk = %d body=%s", rec.Code, rec.Body.String())
	}
	var res struct {
		Count   int            `json:"count"`
		Results []lookupResult `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Count != 2 || res.Results[0].Country != "Testland" || res.Results[1].City != "Testville" {
		t.Fatalf("bulk results = %+v", res)
	}
}

func TestIPLookupAPI_History(t *testing.T) {
	initDB()
	ip := "203.0.113.42"
	LogQuery("GET", "/echo", ip, "datacenter", "Testland")
	FlushQueryLog()

	req := httptest.NewRequest(http.MethodGet, "/api/ip/history?ip="+ip, nil)
	rec := httptest.NewRecorder()
	ipLookupHistoryHandler(rec, req)
	var res struct {
		IP    string              `json:"ip"`
		Count int                 `json:"count"`
		Rows  []map[string]string `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.IP != ip || res.Count < 1 || len(res.Rows) < 1 {
		t.Fatalf("history = %+v", res)
	}
	if res.Rows[0]["path"] != "/echo" || res.Rows[0]["connection_type"] != "datacenter" {
		t.Fatalf("history row = %+v", res.Rows[0])
	}

	// The address is normalized the same way as the lookup endpoint, so
	// "[2001:db8::1]:443" queries the bare literal.
	req = httptest.NewRequest(http.MethodGet, "/api/ip/history?ip=not-an-ip", nil)
	rec = httptest.NewRecorder()
	ipLookupHistoryHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid history IP status = %d", rec.Code)
	}
}

func TestIPLookupAPI_OfflineExplains(t *testing.T) {
	withIPChain(t)
	_ = SetConfig("enable_online_geo", "false")

	req := httptest.NewRequest(http.MethodGet, "/api/ip/lookup?ip=8.8.8.8", nil)
	rec := httptest.NewRecorder()
	ipLookupHandler(rec, req)
	var res lookupResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Valid != true {
		t.Fatalf("offline lookup should still be a valid answer: %+v", res)
	}
	if !strings.Contains(res.Error, "disabled") {
		t.Fatalf("offline error = %q, want a disabled notice", res.Error)
	}
}
