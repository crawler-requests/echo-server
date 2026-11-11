package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/crawler-requests/echo-server/iplookup"
)

// withIPChain gives a test a fresh provider chain and restores every global it
// touched (config keys, the manager, the result cache).
func withIPChain(t *testing.T) {
	t.Helper()
	prevProviders := GetConfig(ipProvidersKey)
	prevOnline := GetConfig("enable_online_geo")
	prevGeoProvider := GetConfig("geo_provider")
	prevToken := GetConfig("ipinfo_token")

	resetChain := func() {
		ipMgrMu.Lock()
		ipLookupMgr = nil
		ipMgrMu.Unlock()
	}
	resetChain()
	_ = SetConfig(ipProvidersKey, "")
	_ = SetConfig("enable_online_geo", "true")
	_ = SetConfig("geo_provider", "auto")
	_ = SetConfig("ipinfo_token", "")
	resetGeoCache()

	t.Cleanup(func() {
		_ = SetConfig(ipProvidersKey, prevProviders)
		_ = SetConfig("enable_online_geo", prevOnline)
		_ = SetConfig("geo_provider", prevGeoProvider)
		_ = SetConfig("ipinfo_token", prevToken)
		resetChain()
		resetGeoCache()
	})
}

func TestIPProviderChain_HTTPFallback(t *testing.T) {
	withIPChain(t)

	var firstCalls atomic.Int32
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstCalls.Add(1)
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer down.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"ip":%q,"country":"Testland","region":"West","city":"Testville","asn":"AS64500","is_hosting":true}`, r.URL.Query().Get("ip"))
	}))
	defer up.Close()

	m := ipLookupManager()
	if _, err := m.Upsert(iplookup.Config{
		Name: "down", Kind: iplookup.KindHTTP, Enabled: true, Priority: 90,
		URL: down.URL + "/lookup?ip={ip}",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Upsert(iplookup.Config{
		Name: "upstream", Kind: iplookup.KindHTTP, Enabled: true, Priority: 80,
		URL: up.URL + "/lookup?ip={ip}",
	}); err != nil {
		t.Fatal(err)
	}

	info := fetchIPInfo("198.51.100.7")
	if info == nil {
		t.Fatal("fetchIPInfo returned nil")
	}
	if info.GeoSource != "upstream" {
		t.Fatalf("geo_source = %q, want upstream (fallback provider)", info.GeoSource)
	}
	if info.Country != "Testland" || info.City != "Testville" || info.ASN != "AS64500" {
		t.Fatalf("geo fields = %+v", info)
	}
	if info.IsHosting == nil || !*info.IsHosting || info.ConnectionType != "datacenter" {
		t.Fatalf("privacy/classification = %+v", info)
	}
	if firstCalls.Load() != 1 {
		t.Fatalf("first provider calls = %d", firstCalls.Load())
	}
	// The failing provider's error is visible in the chain status.
	for _, st := range m.List() {
		if st.Name == "down" && (st.Failures != 1 || st.LastError == "") {
			t.Fatalf("down stats = %+v", st)
		}
	}
}

func TestIPProviderGate_OfflineBlocksEveryProvider(t *testing.T) {
	withIPChain(t)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, `{"country":"ShouldNotAppear"}`)
	}))
	defer srv.Close()

	if _, err := ipLookupManager().Upsert(iplookup.Config{
		Name: "custom", Kind: iplookup.KindHTTP, Enabled: true, Priority: 100,
		URL: srv.URL + "/?ip={ip}",
	}); err != nil {
		t.Fatal(err)
	}

	_ = SetConfig("enable_online_geo", "false")
	info := fetchIPInfo("198.51.100.8")
	if calls.Load() != 0 || info.GeoSource != "local" || info.Country != "" {
		t.Fatalf("offline must not call providers: calls=%d info=%+v", calls.Load(), info)
	}

	// The chain reports the provider as gated rather than silently missing.
	for _, st := range ipLookupManager().List() {
		if st.Name == "custom" && !st.Gated {
			t.Fatalf("custom provider should be marked gated while offline: %+v", st)
		}
	}
}

func TestIPProviderGate_LegacySpecificDriver(t *testing.T) {
	withIPChain(t)
	_ = SetConfig("geo_provider", "ipapi")
	builtin := iplookup.Config{Name: "ipwhois", Kind: iplookup.KindBuiltin, Driver: "ipwhois", Enabled: true}
	if ipProviderGate(builtin) {
		t.Fatal("geo_provider=ipapi must skip the ipwhois builtin")
	}
	custom := iplookup.Config{Name: "cloud", Kind: iplookup.KindHTTP, Enabled: true}
	if !ipProviderGate(custom) {
		t.Fatal("custom providers must stay active when a built-in driver is selected")
	}
}

func TestIPProviderRank_TokenPromotesIpinfo(t *testing.T) {
	withIPChain(t)
	cfg := iplookup.Config{Name: "ipinfo", Kind: iplookup.KindBuiltin, Driver: "ipinfo"}
	if got := ipProviderRank(cfg, 5); got != 5 {
		t.Fatalf("without token rank = %d, want 5", got)
	}
	_ = SetConfig("ipinfo_token", "secret")
	if got := ipProviderRank(cfg, 5); got != 1000 {
		t.Fatalf("with token rank = %d, want 1000", got)
	}
	other := iplookup.Config{Name: "ipwhois", Kind: iplookup.KindBuiltin, Driver: "ipwhois"}
	if got := ipProviderRank(other, 20); got != 20 {
		t.Fatalf("other drivers must keep their priority, got %d", got)
	}
}

func TestIPProvidersAPI_ListUpsertDeleteTest(t *testing.T) {
	withIPChain(t)

	// GET lists the three built-in drivers in chain order.
	req := httptest.NewRequest(http.MethodGet, "/api/ipproviders", nil)
	rec := httptest.NewRecorder()
	ipProvidersHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	var list []iplookup.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(list))
	for _, st := range list {
		names = append(names, st.Name)
		if !st.Builtin {
			t.Fatalf("builtin flag missing: %+v", st)
		}
	}
	if strings.Join(names, ",") != "ipwhois,ipapi,ipinfo" {
		t.Fatalf("builtin order = %v", names)
	}

	// A cloud API with a mapping is accepted and can be tested immediately.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"geo":{"country":"ApiLand","city":"ApiCity"},"asn":64512}`)
	}))
	defer srv.Close()
	body, _ := json.Marshal(map[string]any{
		"name": "cloud", "kind": "http", "enabled": true, "priority": 200,
		"url":     srv.URL + "/{ip}",
		"mapping": map[string]string{"country": "geo.country", "city": "geo.city", "asn": "asn"},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/ipproviders", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	ipProvidersHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d body=%s", rec.Code, rec.Body.String())
	}
	var st iplookup.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Name != "cloud" || st.Kind != iplookup.KindHTTP {
		t.Fatalf("upserted = %+v", st)
	}

	// Test endpoint bypasses the cache and names the answering provider.
	req = httptest.NewRequest(http.MethodPost, "/api/ipproviders/test", strings.NewReader(`{"ip":"198.51.100.9"}`))
	rec = httptest.NewRecorder()
	ipProvidersTestHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("test endpoint = %d body=%s", rec.Code, rec.Body.String())
	}
	var tr struct {
		Provider string        `json:"provider"`
		Info     iplookup.Info `json:"info"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tr); err != nil {
		t.Fatal(err)
	}
	if tr.Provider != "cloud" || tr.Info.Country != "ApiLand" || tr.Info.ASN != "AS64512" {
		t.Fatalf("test result = %+v", tr)
	}

	// Validation: no placeholder, and builtin deletion.
	bad, _ := json.Marshal(map[string]any{"name": "bad", "kind": "http", "url": "http://x/"})
	req = httptest.NewRequest(http.MethodPost, "/api/ipproviders", bytes.NewReader(bad))
	rec = httptest.NewRecorder()
	ipProvidersHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad url status = %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodDelete, "/api/ipproviders?name=ipwhois", nil)
	rec = httptest.NewRecorder()
	ipProvidersHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("builtin delete status = %d", rec.Code)
	}

	// Deleting the custom provider works.
	req = httptest.NewRequest(http.MethodDelete, "/api/ipproviders?name=cloud", nil)
	rec = httptest.NewRecorder()
	ipProvidersHandler(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete custom = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestIPProviderTestEndpoint_NoAnswer(t *testing.T) {
	withIPChain(t)
	_ = SetConfig("enable_online_geo", "false")
	req := httptest.NewRequest(http.MethodPost, "/api/ipproviders/test", strings.NewReader(`{"ip":"198.51.100.10"}`))
	rec := httptest.NewRecorder()
	ipProvidersTestHandler(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no provider answered") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}
