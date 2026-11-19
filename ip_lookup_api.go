package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// IP location lookup as a first-class API, separate from the echo endpoint.
//
// The echo path answers "who is calling me": it infers the address from
// X-Forwarded-For or the TCP peer and returns everything the request carries.
// This API answers "tell me about this address": the caller names the IP
// explicitly, so it works from the console, from scripts, and for addresses
// that are not the caller's own (log triage, abuse reports, batch enrichment).

const (
	// maxLookupIPs caps one request so a script cannot turn the service into
	// an unbounded stream of upstream calls.
	maxLookupIPs = 100
	// lookupBodyLimit bounds POST bodies (100 addresses plus JSON overhead).
	lookupBodyLimit = 64 << 10
	// lookupWorkers parallelizes batch lookups (cache misses cost an upstream
	// round trip each); the provider chain records stats under its own lock.
	lookupWorkers = 4
)

// lookupRequest is the POST body of /api/ip/lookup.
type lookupRequest struct {
	IPs []string `json:"ips"`
	IP  string   `json:"ip"`
	// NoCache forces a fresh provider query, bypassing the result cache.
	NoCache bool `json:"nocache"`
}

// lookupResult is one address answer plus why it may be empty.
type lookupResult struct {
	*IPInfo
	Input  string `json:"input"`
	Valid  bool   `json:"valid"`
	Error  string `json:"error,omitempty"`
	Cached bool   `json:"cached"`
}

var ipLiteralSep = regexp.MustCompile(`[\s,;]+`)

// parseLookupTargets validates and de-duplicates the requested addresses. Only
// bare IP literals are accepted (no hostnames, no schemes), so a typo fails
// loudly instead of producing an unrelated answer for some resolved host.
func parseLookupTargets(req lookupRequest) ([]string, error) {
	raw := make([]string, 0, len(req.IPs)+1)
	if strings.TrimSpace(req.IP) != "" {
		raw = append(raw, req.IP)
	}
	raw = append(raw, req.IPs...)
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, r := range raw {
		for _, part := range ipLiteralSep.Split(strings.TrimSpace(r), -1) {
			if part == "" {
				continue
			}
			ip := canonicalIP(part)
			if ip == "" {
				return nil, fmt.Errorf("invalid IP address %q (hostnames are not accepted)", part)
			}
			if seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ip or ips is required")
	}
	if len(out) > maxLookupIPs {
		return nil, fmt.Errorf("too many addresses: %d (max %d)", len(out), maxLookupIPs)
	}
	return out, nil
}

// canonicalIP accepts a bare IPv4/IPv6 literal, with an optional bracketed
// IPv6 form or a trailing :port, and returns the normalized address.
func canonicalIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	if s == "" {
		return ""
	}
	// Zone identifiers (fe80::1%eth0) are meaningful locally; strip them so the
	// answer is stable, and the address still parses.
	if i := strings.IndexByte(s, '%'); i > 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// ipLookupHandler serves GET /api/ip/lookup?ip=...&nocache=1 and
// POST /api/ip/lookup with {"ip"|"ips", "nocache"}.
func ipLookupHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		req := lookupRequest{
			IP:      strings.TrimSpace(r.URL.Query().Get("ip")),
			NoCache: truthy(r.URL.Query().Get("nocache")),
		}
		if v := strings.TrimSpace(r.URL.Query().Get("ips")); v != "" {
			req.IPs = []string{v}
		}
		lookupAndRespond(w, r, req)
	case http.MethodPost:
		var req lookupRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, lookupBodyLimit)).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		lookupAndRespond(w, r, req)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func lookupAndRespond(w http.ResponseWriter, r *http.Request, req lookupRequest) {
	ips, err := parseLookupTargets(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	results := runLookups(ips, req.NoCache)
	// One address answers with the IP object itself so jq/curl pipelines stay
	// simple; several answer with a list and a small summary.
	if len(results) == 1 {
		writeJSON(w, results[0])
		return
	}
	writeJSON(w, map[string]any{
		"count":    len(results),
		"answered": answeredCount(results),
		"results":  results,
	})
}

// ipBulkHandler answers POST /api/ip/lookup/bulk with a plain-text body (one
// address per line, or comma separated) because that is what shell scripts and
// spreadsheets produce.
func ipBulkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, lookupBodyLimit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	ips, err := parseLookupTargets(lookupRequest{IPs: []string{string(body)}})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	results := runLookups(ips, false)
	writeJSON(w, map[string]any{
		"count":    len(results),
		"answered": answeredCount(results),
		"results":  results,
	})
}

// ipLookupHistoryHandler lists query-log rows for one address, i.e. whether
// that IP actually called the echo endpoint.
func ipLookupHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := canonicalIP(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "invalid or missing ip", http.StatusBadRequest)
		return
	}
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 500 {
		limit = v
	}
	rows := fetchLogs(logFilter{IP: ip, Limit: limit})
	writeJSON(w, map[string]any{"ip": ip, "count": len(rows), "rows": rows})
}

// runLookups resolves every address, running a few at a time but preserving
// input order so batch output lines up with the caller's list.
func runLookups(ips []string, noCache bool) []lookupResult {
	results := make([]lookupResult, len(ips))
	var wg sync.WaitGroup
	sem := make(chan struct{}, lookupWorkers)
	for i, ip := range ips {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = lookupOneIP(ip, noCache)
		}(i, ip)
	}
	wg.Wait()
	return results
}

// answeredCount counts results that a provider actually filled in (as opposed
// to the local-table baseline).
func answeredCount(results []lookupResult) int {
	n := 0
	for _, res := range results {
		if res.IPInfo != nil && infoHasLookupData(res.IPInfo) {
			n++
		}
	}
	return n
}

// lookupOneIP always returns a result. An unusable address explains itself
// instead of coming back as an empty object, so batch callers can tell "wrong
// input" apart from "providers had nothing".
func lookupOneIP(ip string, noCache bool) lookupResult {
	if noCache {
		geoCacheDelete(ip)
	}
	cached := geoCacheGet(ip) != nil
	info := fetchIPInfo(ip)
	res := lookupResult{Input: ip, Valid: info != nil, Cached: cached, IPInfo: info}
	if info == nil {
		res.Error = "invalid IP address"
		return res
	}
	if !infoHasLookupData(info) {
		parsed := net.ParseIP(ip)
		switch {
		case geoProvider() == "offline" || GetConfig("enable_online_geo") == "false":
			res.Error = "online lookup disabled; only local tables were used"
		case parsed != nil && (parsed.IsPrivate() || parsed.IsLoopback()):
			res.Error = "private or loopback address; no external lookup performed"
		case parsed != nil && parsed.IsUnspecified():
			res.Error = "unspecified address; nothing to look up"
		case parsed != nil && (parsed.IsMulticast() || parsed.IsLinkLocalUnicast() ||
			parsed.IsLinkLocalMulticast() || parsed.IsInterfaceLocalMulticast()):
			res.Error = "non-routable address (multicast/link-local); no external lookup performed"
		default:
			res.Error = "no provider returned data"
		}
	}
	return res
}
