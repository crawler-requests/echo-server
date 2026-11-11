package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crawler-requests/echo-server/ipclass"
)

// geoProvider returns the effective IP-intel provider from admin config.
// "offline" means local tables only (no outbound lookups).
// Settings:
//   - enable_online_geo=false  -> "offline"
//   - geo_provider             -> one of auto|ipwhois|ipapi|ipinfo|offline (default auto)
//   - ipinfo_token             -> optional token; when set, ipinfo's loc+privacy
//     fields (street-level accuracy + hosting/proxy/vpn/tor booleans) are used.
func geoProvider() string {
	if GetConfig("enable_online_geo") == "false" {
		return "offline"
	}
	p := strings.ToLower(strings.TrimSpace(GetConfig("geo_provider")))
	switch p {
	case "ipwhois", "ipapi", "ipinfo", "offline":
		return p
	}
	return "auto"
}

// geoData is the provider-normalized IP geo/privacy result.
type geoData struct {
	IP          string
	Continent   string
	Country     string
	CountryCode string
	Region      string
	City        string
	Postal      string
	Timezone    string
	UTCOffset   string
	Lat, Lon    float64
	ASN         string
	ASNName     string
	Org         string
	ISP         string
	// Privacy booleans come only from ipinfo with a token.
	IsProxy   *bool
	IsVPN     *bool
	IsTor     *bool
	IsHosting *bool
	Source    string // ipwhois | ipapi | ipinfo | local
}

// HasPrivacy reports whether authoritative privacy labels are available.
func (g *geoData) HasPrivacy() bool {
	if g == nil {
		return false
	}
	return g.IsProxy != nil || g.IsVPN != nil || g.IsTor != nil || g.IsHosting != nil
}

var geoHTTP = &http.Client{Timeout: 4 * time.Second}

// httpGetJSON performs a GET with a browser-ish UA and a generous but bounded
// response size, returning the raw body.
func httpGetJSON(rawURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "echo-server/1.0 (+https://github.com/crawler-requests/echo-server)")
	resp, err := geoHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("geo provider %s: status %d", rawURL, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// --- memory cache with TTL (results change rarely; avoids hammering free APIs)
var geoCache = struct {
	sync.Mutex
	m     map[string]geoCacheEntry
	order []string
}{m: map[string]geoCacheEntry{}}

const geoCacheMax = 4096

type geoCacheEntry struct {
	info   *IPInfo
	expire time.Time
}

func geoCacheTTL() time.Duration {
	if h, err := strconv.Atoi(GetConfig("geo_cache_ttl")); err == nil && h > 0 {
		return time.Duration(h) * time.Hour
	}
	return 24 * time.Hour
}

func geoCacheGet(ip string) *IPInfo {
	geoCache.Lock()
	defer geoCache.Unlock()
	e, ok := geoCache.m[ip]
	if !ok || time.Now().After(e.expire) {
		return nil
	}
	return e.info
}

func geoCachePut(ip string, info *IPInfo) {
	geoCache.Lock()
	defer geoCache.Unlock()
	geoCache.m[ip] = geoCacheEntry{info: info, expire: time.Now().Add(geoCacheTTL())}
	geoCache.order = append(geoCache.order, ip)
	for len(geoCache.order) > geoCacheMax {
		old := geoCache.order[0]
		geoCache.order = geoCache.order[1:]
		delete(geoCache.m, old)
	}
}

// lookupGeo walks the provider chain (built-in drivers plus any operator-added
// cloud APIs / local scripts) and returns the first usable answer. The chain,
// its ordering and its fallback statistics live in ip_providers.go.
func lookupGeo(ip string) *geoData {
	if geoProvider() == "offline" {
		return nil
	}
	info, _, err := ipLookupManager().Lookup(ip)
	if err != nil || info == nil {
		return nil
	}
	return lookupInfoToGeo(info)
}

// lookupIPWhoIs: https://ipwho.is/<ip> — free, no key, includes lat/lon.
func lookupIPWhoIs(ip string) (*geoData, error) {
	body, err := httpGetJSON("https://ipwho.is/" + ip)
	if err != nil {
		return nil, err
	}
	var d struct {
		Success     bool    `json:"success"`
		IP          string  `json:"ip"`
		Continent   string  `json:"continent"`
		Country     string  `json:"country"`
		CountryCode string  `json:"country_code"`
		Region      string  `json:"region"`
		City        string  `json:"city"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		Postal      string  `json:"postal"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
		Timezone struct {
			ID  string `json:"id"`
			UTC string `json:"utc"`
		} `json:"timezone"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	if !d.Success {
		return nil, fmt.Errorf("ipwhois lookup failed")
	}
	g := &geoData{
		IP:          firstNonEmpty(d.IP, ip),
		Continent:   d.Continent,
		Country:     d.Country,
		CountryCode: d.CountryCode,
		Region:      d.Region,
		City:        d.City,
		Postal:      d.Postal,
		Lat:         d.Latitude,
		Lon:         d.Longitude,
		Org:         d.Connection.Org,
		ISP:         d.Connection.ISP,
		Timezone:    d.Timezone.ID,
		UTCOffset:   d.Timezone.UTC,
		Source:      "ipwhois",
	}
	if d.Connection.ASN != 0 {
		g.ASN = fmt.Sprintf("AS%d", d.Connection.ASN)
	}
	return g, nil
}

// lookupIPAPI: http://ip-api.com/json/<ip> — free (HTTP only), 45 req/min/IP.
func lookupIPAPI(ip string) (*geoData, error) {
	u := "http://ip-api.com/json/" + ip +
		"?fields=status,message,query,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname"
	body, err := httpGetJSON(u)
	if err != nil {
		return nil, err
	}
	var d struct {
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		Query       string  `json:"query"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		Region      string  `json:"region"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		Zip         string  `json:"zip"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Timezone    string  `json:"timezone"`
		ISP         string  `json:"isp"`
		Org         string  `json:"org"`
		AS          string  `json:"as"`
		ASName      string  `json:"asname"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	if d.Status != "success" {
		return nil, fmt.Errorf("ip-api lookup failed: %s", d.Message)
	}
	g := &geoData{
		IP:          firstNonEmpty(d.Query, ip),
		Country:     d.Country,
		CountryCode: d.CountryCode,
		Region:      firstNonEmpty(d.RegionName, d.Region),
		City:        d.City,
		Postal:      d.Zip,
		Lat:         d.Lat,
		Lon:         d.Lon,
		Timezone:    d.Timezone,
		ISP:         d.ISP,
		Org:         d.Org,
		ASNName:     d.ASName,
		Source:      "ipapi",
	}
	if as := strings.Fields(d.AS); len(as) > 0 {
		g.ASN = as[0]
	}
	return g, nil
}

// lookupIPInfo: https://ipinfo.io/<ip>/json[?token=...] plus /privacy when a
// token is configured. Without a token loc is absent; with a token we get
// street-level precision and authoritative hosting/proxy/vpn/tor booleans.
func lookupIPInfo(ip string) (*geoData, error) {
	token := url.QueryEscape(GetConfig("ipinfo_token"))
	suffix := ""
	if token != "" {
		suffix = "?token=" + token
	}
	body, err := httpGetJSON("https://ipinfo.io/" + ip + "/json" + suffix)
	if err != nil {
		return nil, err
	}
	var d struct {
		IP       string `json:"ip"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Org      string `json:"org"`
		Postal   string `json:"postal"`
		Timezone string `json:"timezone"`
		Loc      string `json:"loc"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	if d.IP == "" && d.Country == "" {
		return nil, fmt.Errorf("ipinfo lookup returned no data")
	}
	g := &geoData{
		IP:          firstNonEmpty(d.IP, ip),
		City:        d.City,
		Region:      d.Region,
		Country:     d.Country,
		Postal:      d.Postal,
		Timezone:    d.Timezone,
		Source:      "ipinfo",
		CountryCode: normalizeCountryCode(d.Country),
	}
	if d.Loc != "" {
		if parts := strings.Split(d.Loc, ","); len(parts) == 2 {
			g.Lat, _ = strconv.ParseFloat(parts[0], 64)
			g.Lon, _ = strconv.ParseFloat(parts[1], 64)
		}
	}
	// org is "AS15169 Google LLC"
	if asn, org := splitASN(d.Org); asn != "" {
		g.ASN = asn
		g.Org = org
	} else {
		g.Org = d.Org
	}
	// privacy only with a token
	if token != "" {
		if pbody, perr := httpGetJSON("https://ipinfo.io/" + ip + "/privacy" + suffix); perr == nil {
			var pr struct {
				Proxy   bool `json:"proxy"`
				VPN     bool `json:"vpn"`
				Tor     bool `json:"tor"`
				Hosting bool `json:"hosting"`
			}
			if json.Unmarshal(pbody, &pr) == nil {
				g.IsProxy = boolPtr(pr.Proxy)
				g.IsVPN = boolPtr(pr.VPN)
				g.IsTor = boolPtr(pr.Tor)
				g.IsHosting = boolPtr(pr.Hosting)
			}
		}
	}
	return g, nil
}

func boolPtr(b bool) *bool { return &b }

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func splitASN(org string) (asn, name string) {
	if fields := strings.Fields(org); len(fields) >= 2 && strings.HasPrefix(fields[0], "AS") {
		return fields[0], strings.Join(fields[1:], " ")
	}
	return "", org
}

// normalizeCountryCode returns the value unchanged when it already looks like
// an ISO 3166-1 alpha-2 code (which is what ipinfo emits), else "".
func normalizeCountryCode(v string) string {
	if len(v) == 2 {
		return strings.ToUpper(v)
	}
	return ""
}

// fetchIPInfo is the shipped entry point used by echoHandler. It returns a
// complete IPInfo with connection classification always filled; geolocation is
// best-effort from the configured provider and honestly empty when offline.
func fetchIPInfo(ip string) *IPInfo {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	p := net.ParseIP(ip)
	if p == nil {
		return &IPInfo{IP: ip, ConnectionType: "unknown", GeoSource: "local"}
	}
	// Local/private addresses must never trigger a network lookup.
	if p.IsLoopback() || p.IsPrivate() {
		return &IPInfo{IP: ip, ConnectionType: ipclass.Classify(ip), GeoSource: "local"}
	}

	// Baseline from local tables (never depends on the network).
	ct := ipclass.Classify(ip)

	if geoProvider() == "offline" {
		info := &IPInfo{IP: ip, ConnectionType: ct, GeoSource: "local"}
		finalizeClassification(info, nil)
		return info
	}
	if cached := geoCacheGet(ip); cached != nil {
		return cached
	}

	g := lookupGeo(ip)
	info := geoDataToIPInfo(ip, g, ct)
	finalizeClassification(info, g)
	geoCachePut(ip, info)
	return info
}

func geoDataToIPInfo(ip string, g *geoData, ct string) *IPInfo {
	info := &IPInfo{
		IP:             ip,
		ConnectionType: ct,
		GeoSource:      "local",
	}
	if g == nil {
		return info
	}
	if g.IP != "" {
		info.IP = g.IP
	}
	info.Country = g.Country
	info.CountryCode = g.CountryCode
	info.Region = g.Region
	info.City = g.City
	info.Postal = g.Postal
	info.Timezone = g.Timezone
	info.UTCOffset = g.UTCOffset
	info.Continent = g.Continent
	info.Latitude = g.Lat
	info.Longitude = g.Lon
	info.ASN = g.ASN
	info.ASNName = g.ASNName
	info.Org = g.Org
	info.ISP = g.ISP
	info.IsProxy = g.IsProxy
	info.IsVPN = g.IsVPN
	info.IsTor = g.IsTor
	info.IsHosting = g.IsHosting
	info.GeoSource = g.Source
	return info
}

// finalizeClassification merges privacy signals (when authoritative) and the
// ASN/org datacenter heuristic into the connection_type label.
func finalizeClassification(info *IPInfo, g *geoData) {
	if info == nil {
		return
	}
	// Authoritative privacy labels beat local tables.
	if g != nil && g.HasPrivacy() {
		if (g.IsProxy != nil && *g.IsProxy) || (g.IsVPN != nil && *g.IsVPN) || (g.IsTor != nil && *g.IsTor) {
			info.ConnectionType = "residential_proxy"
			return
		}
		if g.IsHosting != nil && *g.IsHosting {
			info.ConnectionType = "datacenter"
			return
		}
	}
	// Local-only fallback: unknown + a datacenter-looking org -> datacenter.
	if info.ConnectionType == "unknown" && ipclass.OrgLooksDatacenter(info.Org) {
		info.ConnectionType = "datacenter"
		return
	}
}
