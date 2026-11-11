package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/crawler-requests/echo-server/iplookup"
)

// IP-intelligence providers. Every source of IP geo/ASN/privacy data is one
// provider in a priority-ordered chain: the built-in drivers (ipwho.is,
// ip-api.com, ipinfo.io) plus any number of user-defined cloud APIs (kind=http)
// or local scripts (kind=command). The first provider that returns usable data
// wins; a failing or rate-limited source simply falls through to the next one.
//
// The legacy admin switches keep their meaning on top of the chain:
//   - enable_online_geo=false disables every online provider (custom included);
//   - geo_provider=ipwhois|ipapi|ipinfo restricts the built-in drivers to that
//     one (custom providers still participate);
//   - geo_provider=auto runs the whole chain, with ipinfo moved to the front
//     when an ipinfo token is configured.
const ipProvidersKey = "ip_lookup_providers"

var (
	ipMgrMu     sync.Mutex
	ipLookupMgr *iplookup.Manager
)

// saveIPProviders persists the chain through the SQLite config table.
func saveIPProviders(cfgs []iplookup.Config) error {
	raw, err := json.Marshal(cfgs)
	if err != nil {
		return err
	}
	return SetConfig(ipProvidersKey, string(raw))
}

// loadIPProvidersConfig returns the persisted list plus an optional env list
// (IP_LOOKUP_PROVIDERS, a JSON array applied after the persisted one).
func loadIPProvidersConfig() (string, string) {
	return GetConfig(ipProvidersKey), os.Getenv("IP_LOOKUP_PROVIDERS")
}

// ipProviderGate applies the global switches at lookup time. The Gate receives
// a copy of the provider config, so no stored configuration is rewritten.
func ipProviderGate(cfg iplookup.Config) bool {
	switch geoProvider() {
	case "offline":
		return false
	case "auto":
		return true
	default:
		// A specific built-in API was selected: skip the other built-ins but
		// keep custom providers in the chain.
		return cfg.Kind != iplookup.KindBuiltin || cfg.Driver == geoProvider()
	}
}

// ipProviderRank moves ipinfo to the front while an ipinfo token is configured
// (it then provides street-level coordinates and authoritative privacy flags).
func ipProviderRank(cfg iplookup.Config, priority int) int {
	if cfg.Kind == iplookup.KindBuiltin && cfg.Driver == "ipinfo" && GetConfig("ipinfo_token") != "" {
		return 1000
	}
	return priority
}

// builtinGeoProvider adapts one of the compiled parsers in ip_geo.go to the
// provider interface.
type builtinGeoProvider struct {
	fn func(string) (*geoData, error)
}

func (b builtinGeoProvider) Lookup(ip string) (*iplookup.Info, error) {
	g, err := b.fn(ip)
	if err != nil {
		return nil, err
	}
	return geoToLookupInfo(g), nil
}

// initIPProviders builds the chain once: register the built-in drivers, seed
// them, then lay the persisted/env providers over the defaults.
func initIPProviders() {
	ipMgrMu.Lock()
	defer ipMgrMu.Unlock()
	if ipLookupMgr != nil {
		return
	}
	m := iplookup.New(iplookup.Options{
		Saver:      saveIPProviders,
		LoadConfig: loadIPProvidersConfig,
		Gate:       ipProviderGate,
		Rank:       ipProviderRank,
		UserAgent:  "echo-server/1.0 (+https://github.com/crawler-requests/echo-server)",
	})
	m.RegisterDriver("ipwhois", func(iplookup.Config) (iplookup.Provider, error) {
		return builtinGeoProvider{fn: lookupIPWhoIs}, nil
	})
	m.RegisterDriver("ipapi", func(iplookup.Config) (iplookup.Provider, error) {
		return builtinGeoProvider{fn: lookupIPAPI}, nil
	})
	m.RegisterDriver("ipinfo", func(iplookup.Config) (iplookup.Provider, error) {
		return builtinGeoProvider{fn: lookupIPInfo}, nil
	})
	// Default order mirrors the legacy auto mode: ipwho.is, then ip-api.com,
	// then ipinfo.io (moved to the front by Rank when a token is set).
	for _, cfg := range []iplookup.Config{
		{Name: "ipwhois", Kind: iplookup.KindBuiltin, Driver: "ipwhois", Enabled: true, Priority: 20},
		{Name: "ipapi", Kind: iplookup.KindBuiltin, Driver: "ipapi", Enabled: true, Priority: 10},
		{Name: "ipinfo", Kind: iplookup.KindBuiltin, Driver: "ipinfo", Enabled: true, Priority: 5},
	} {
		if err := m.SeedBuiltin(cfg); err != nil {
			log.Printf("iplookup: seed %s: %v", cfg.Name, err)
		}
	}
	m.Init()
	ipLookupMgr = m
}

// ipLookupManager returns the process-wide chain, creating it on first use.
func ipLookupManager() *iplookup.Manager {
	initIPProviders()
	ipMgrMu.Lock()
	defer ipMgrMu.Unlock()
	return ipLookupMgr
}

// geoToLookupInfo converts the legacy normalized struct to the provider
// contract.
func geoToLookupInfo(g *geoData) *iplookup.Info {
	if g == nil {
		return nil
	}
	return &iplookup.Info{
		IP:          g.IP,
		Continent:   g.Continent,
		Country:     g.Country,
		CountryCode: g.CountryCode,
		Region:      g.Region,
		City:        g.City,
		Postal:      g.Postal,
		Timezone:    g.Timezone,
		UTCOffset:   g.UTCOffset,
		Latitude:    g.Lat,
		Longitude:   g.Lon,
		ASN:         g.ASN,
		ASNName:     g.ASNName,
		Org:         g.Org,
		ISP:         g.ISP,
		IsProxy:     g.IsProxy,
		IsVPN:       g.IsVPN,
		IsTor:       g.IsTor,
		IsHosting:   g.IsHosting,
		Source:      g.Source,
	}
}

func lookupInfoToGeo(i *iplookup.Info) *geoData {
	if i == nil {
		return nil
	}
	return &geoData{
		IP:          i.IP,
		Continent:   i.Continent,
		Country:     i.Country,
		CountryCode: i.CountryCode,
		Region:      i.Region,
		City:        i.City,
		Postal:      i.Postal,
		Timezone:    i.Timezone,
		UTCOffset:   i.UTCOffset,
		Lat:         i.Latitude,
		Lon:         i.Longitude,
		ASN:         i.ASN,
		ASNName:     i.ASNName,
		Org:         i.Org,
		ISP:         i.ISP,
		IsProxy:     i.IsProxy,
		IsVPN:       i.IsVPN,
		IsTor:       i.IsTor,
		IsHosting:   i.IsHosting,
		Source:      i.Source,
	}
}

// ---------------------------------------------------------------------------
// Admin API

// ipProvidersHandler drives the chain: GET lists it, POST upserts one provider,
// DELETE removes a custom one.
func ipProvidersHandler(w http.ResponseWriter, r *http.Request) {
	m := ipLookupManager()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, m.List())
	case http.MethodPost:
		var cfg iplookup.Config
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&cfg); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		st, err := m.Upsert(cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, st)
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			name = r.URL.Query().Get("provider")
		}
		if err := m.Delete(name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ipProvidersTestHandler runs the chain for one IP right now, bypassing the
// result cache, and reports which provider answered. The admin UI uses it to
// validate a new cloud API before relying on it.
func ipProvidersTestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		http.Error(w, "ip is required", http.StatusBadRequest)
		return
	}
	info, provider, err := ipLookupManager().Lookup(req.IP)
	if err != nil {
		writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if info == nil {
		writeJSONStatus(w, http.StatusBadGateway, map[string]string{
			"error": "no provider answered (check that online lookups are enabled and at least one provider is active)",
		})
		return
	}
	writeJSON(w, map[string]any{"provider": provider, "info": info})
}

// writeJSONStatus writes a JSON body with an explicit HTTP status.
func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
