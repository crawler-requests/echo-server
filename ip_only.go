package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

// Fast IP-only endpoint.
//
// The full /echo response costs far more than the caller usually needs: it
// re-parses the ClientHello, computes JA3/JA4/JA4H/h2 fingerprints, runs the
// client-identification model, looks up geography (sometimes over the network)
// and writes a query-log row. A proxy pool that only wants "what is my egress
// IP" pays for all of it.
//
// /ip answers exactly that, in the cheapest way the server can:
//   - no allocation beyond a short string,
//   - no TLS/ClientHello work (ClientHello capture already happens in the
//     connection wrapper; this handler simply never reads it),
//   - no geolocation, no client identification, no SQLite write.
//
// Format: `?format=json` (default) returns {"ip":"1.2.3.4"}; `format=text`
// returns the bare address with a trailing newline (curl-friendly). The
// response is Cache-Control: no-store because the IP is per-connection.
//
// The hot path is deliberately written without fmt/x-encoding/json: on this
// path a single allocation per request is already measurable.

// ipOnlyRequests counts fast-path requests (exposed in /metrics).
var ipOnlyRequests atomic.Uint64

// ipOnlyText is a tiny prebuilt response writer for the common cases.
func ipOnlyHandler(w http.ResponseWriter, r *http.Request) {
	ipOnlyRequests.Add(1)

	ip := extractClientIP(r)
	// extractClientIP already trims; guard against an empty result for a
	// pathological RemoteAddr.
	if ip == "" {
		http.Error(w, "could not determine client IP", http.StatusBadRequest)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// The permissive CORS default matches /echo, so browser-side proxy
	// checkers work the same way.
	if w.Header().Get("Access-Control-Allow-Origin") == "" && GetConfig("cors_origins") == "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}

	format := strings.TrimSpace(r.URL.Query().Get("format"))
	if v := strings.TrimSpace(r.Header.Get("X-Echo-Format")); v != "" {
		format = v
	}
	if strings.EqualFold(format, "text") || strings.EqualFold(format, "plain") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		// One Write, no builder: the address is validated (no quotes or
		// backslashes possible in an IP literal), so the JSON body is safe too.
		_, _ = w.Write([]byte(ip + "\n"))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write([]byte(`{"ip":"` + ip + `"}`))
}

// ipOnlyMetricsLine renders the fast-path counter for the Prometheus output.
func ipOnlyMetricsLine() string {
	return fmt.Sprintf("# HELP echo_ip_only_requests_total Fast /ip requests\n"+
		"# TYPE echo_ip_only_requests_total counter\necho_ip_only_requests_total %d\n",
		ipOnlyRequests.Load())
}
