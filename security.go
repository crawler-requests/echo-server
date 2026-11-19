package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Edge protections for the public echo endpoint. The console (/ui, /api) is
// deliberately exempt from the IP lists and rate limiter: locking yourself out
// of the console would make the settings impossible to undo. Maintenance mode
// likewise only pauses echo traffic.

var rateState = struct {
	sync.Mutex
	buckets map[string]*rateBucket
}{buckets: map[string]*rateBucket{}}

type rateBucket struct {
	count int
	reset time.Time
}

type ipRules struct {
	allow []*net.IPNet
	deny  []*net.IPNet
}

var ipRuleCache = struct {
	sync.Mutex
	allowRaw, denyRaw string
	rules             ipRules
}{}

func parseIPRules(spec string) []*net.IPNet {
	var out []*net.IPNet
	for _, part := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' '
	}) {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "#") {
			continue
		}
		if strings.Contains(part, "/") {
			if _, n, err := net.ParseCIDR(part); err == nil {
				out = append(out, n)
			}
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return out
}

func currentIPRules() ipRules {
	allowRaw := GetConfig("ip_allowlist")
	denyRaw := GetConfig("ip_denylist")
	ipRuleCache.Lock()
	defer ipRuleCache.Unlock()
	if ipRuleCache.allowRaw != allowRaw || ipRuleCache.denyRaw != denyRaw {
		ipRuleCache.allowRaw, ipRuleCache.denyRaw = allowRaw, denyRaw
		ipRuleCache.rules = ipRules{allow: parseIPRules(allowRaw), deny: parseIPRules(denyRaw)}
	}
	return ipRuleCache.rules
}

func ruleMatches(list []*net.IPNet, ip net.IP) bool {
	for _, n := range list {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// checkIP applies the deny list first, then the allow list (an empty allow
// list means "everyone").
func checkIP(ipStr string) (bool, string) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return true, ""
	}
	rules := currentIPRules()
	if ruleMatches(rules.deny, ip) {
		return false, "来源 IP 在拒绝列表中"
	}
	if len(rules.allow) > 0 && !ruleMatches(rules.allow, ip) {
		return false, "来源 IP 不在允许列表中"
	}
	return true, ""
}

// allowRate returns true when the request is within the per-minute budget.
// A limit of 0 disables the limiter.
//
// Two buckets are charged: the address the client claims (X-Forwarded-For or
// the TCP peer) and the TCP peer itself. Charging the peer prevents a client
// from rotating a spoofed X-Forwarded-For value to escape the limit while
// still giving each real client behind a proxy its own budget.
func allowRate(ip, peer string) bool {
	limit, _ := strconv.Atoi(GetConfig("rate_limit_per_min"))
	if limit <= 0 {
		return true
	}
	now := time.Now()
	rateState.Lock()
	defer rateState.Unlock()
	if len(rateState.buckets) > 20000 {
		for k, b := range rateState.buckets {
			if now.After(b.reset) {
				delete(rateState.buckets, k)
			}
		}
	}
	keys := []string{"client:" + ip}
	if peer != "" && peer != ip {
		keys = append(keys, "peer:"+peer)
	}
	// Charge every key or none: checking first keeps a rejected request from
	// spending the other bucket's budget.
	for _, k := range keys {
		if b := rateState.buckets[k]; b != nil && !now.After(b.reset) && b.count >= limit {
			return false
		}
	}
	for _, k := range keys {
		b := rateState.buckets[k]
		if b == nil || now.After(b.reset) {
			rateState.buckets[k] = &rateBucket{count: 1, reset: now.Add(time.Minute)}
			continue
		}
		b.count++
	}
	return true
}

// tcpPeer returns the connection's real peer address, ignoring forwarding
// headers. Used as the anti-spoofing anchor for rate limiting and login
// throttling.
func tcpPeer(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// Credential endpoints (login / setup / register) are not echo traffic, so the
// operator's echo limiter never covered them. They get a separate, always-on
// budget per TCP peer: the peer address is not client-controlled, so rotating
// X-Forwarded-For does not reset it.
const (
	authFailWindow   = 15 * time.Minute
	authFailLimit    = 10 // failed attempts per peer per window
	authAttemptLimit = 30 // total attempts per peer per window
)

var authThrottle = struct {
	sync.Mutex
	peers map[string]*authPeerState
}{peers: map[string]*authPeerState{}}

type authPeerState struct {
	attempts int
	failures int
	window   time.Time
}

// authThrottleAllow meters one credential attempt. It returns ok=false with a
// retry-after when the peer has spent its budget.
func authThrottleAllow(peer string) (bool, time.Duration) {
	now := time.Now()
	authThrottle.Lock()
	defer authThrottle.Unlock()
	if len(authThrottle.peers) > 20000 {
		for k, st := range authThrottle.peers {
			if now.After(st.window) {
				delete(authThrottle.peers, k)
			}
		}
	}
	st := authThrottle.peers[peer]
	if st == nil || now.After(st.window) {
		authThrottle.peers[peer] = &authPeerState{attempts: 1, window: now.Add(authFailWindow)}
		return true, 0
	}
	if st.failures >= authFailLimit || st.attempts >= authAttemptLimit {
		return false, time.Until(st.window)
	}
	st.attempts++
	return true, 0
}

// authThrottleRecord records the outcome so only failures burn the tighter
// failure budget (a busy legitimate user is not locked out by successful logins).
func authThrottleRecord(peer string, failed bool) {
	if !failed {
		return
	}
	authThrottle.Lock()
	defer authThrottle.Unlock()
	if st := authThrottle.peers[peer]; st != nil {
		st.failures++
	}
}

// authThrottleMiddleware guards login/setup/register with the always-on budget.
func authThrottleMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ok, retry := authThrottleAllow(tcpPeer(r)); !ok {
			secs := int(retry.Seconds()) + 1
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			http.Error(w, "too many credential attempts; retry later", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// defaultEchoBodyLimit bounds the echo request body when the operator left
// body_limit_kb at 0. The echo handler reads the whole body into memory, so an
// unset cap is a memory-exhaustion vector; 8 MB is generous for real use.
const defaultEchoBodyLimit = 8 << 20

// isEchoTraffic identifies requests that belong to the public echo surface
// rather than the console, its APIs, health checks or metrics.
func isEchoTraffic(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case p == "/health" || p == "/metrics" || p == "/favicon.ico":
		return false
	case strings.HasPrefix(p, "/api/") || p == "/api":
		return false
	case strings.HasPrefix(p, "/ui"):
		return false
	}
	return true
}

// securityMiddleware wraps the whole mux: baseline headers, CORS, IP rules,
// rate limiting and the optional maintenance window.
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if GetConfig("security_headers") != "false" {
			w.Header().Set("X-XSS-Protection", "0")
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}

		// CORS: only when the operator configured origins. The echo endpoint
		// keeps its historical Access-Control-Allow-Origin: * otherwise.
		if origin := r.Header.Get("Origin"); origin != "" {
			if allowed, ok := corsOriginAllowed(origin); ok && allowed != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowed)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Token, X-API-Key, X-Echo-Format, X-Echo-Fields")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Max-Age", "600")
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}

		if isEchoTraffic(r) {
			ip := extractClientIP(r)
			if ok, reason := checkIP(ip); !ok {
				http.Error(w, reason, http.StatusForbidden)
				return
			}
			// The peer bucket makes a revolving X-Forwarded-For useless as a
			// limiter bypass; the claimed-IP bucket keeps per-client fairness
			// behind a proxy.
			if !allowRate(ip, tcpPeer(r)) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			if GetConfig("maintenance_mode") == "true" && !isAuthorized(r) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintf(w, "service is under maintenance%s\n", maintenanceMessage())
				return
			}
		}

		if kb, _ := strconv.Atoi(GetConfig("body_limit_kb")); kb > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, int64(kb)*1024)
		} else if r.Body != nil && isEchoTraffic(r) {
			// Even with no operator cap, bound the echo body: reading it with
			// io.ReadAll into memory means an unbounded body is a trivial
			// memory-exhaustion vector. 8 MB is far above any request a client
			// would want echoed back (logs show typical bodies are KBs).
			r.Body = http.MaxBytesReader(w, r.Body, defaultEchoBodyLimit)
		}

		next.ServeHTTP(w, r)
	})
}

func maintenanceMessage() string {
	if msg := strings.TrimSpace(GetConfig("maintenance_message")); msg != "" {
		return ": " + msg
	}
	return ""
}

// corsOriginAllowed returns the value to echo in Access-Control-Allow-Origin.
// "" with ok=false means CORS is not configured, so leave the response alone.
func corsOriginAllowed(origin string) (string, bool) {
	cfg := strings.TrimSpace(GetConfig("cors_origins"))
	if cfg == "" {
		return "", false
	}
	for _, o := range strings.Split(cfg, ",") {
		o = strings.TrimSpace(o)
		if o == "*" {
			return "*", true
		}
		if strings.EqualFold(o, origin) {
			return origin, true
		}
	}
	return "", false
}

// startMaintenanceWorker enforces log retention and keeps helper tables tidy.
func startMaintenanceWorker() {
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		time.Sleep(30 * time.Second) // let the server finish booting
		for {
			purgeExpiredLogs()
			_, _ = db.Exec(`DELETE FROM notifications WHERE id NOT IN (SELECT id FROM notifications ORDER BY id DESC LIMIT 500)`)
			<-ticker.C
		}
	}()
}

// purgeExpiredLogs deletes query_log rows older than log_retention_days.
func purgeExpiredLogs() int64 {
	days, _ := strconv.Atoi(GetConfig("log_retention_days"))
	if days <= 0 {
		return 0
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)
	res, err := db.Exec(`DELETE FROM query_log WHERE ts < ?`, cutoff)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		log.Printf("log retention: removed %d query rows older than %d days", n, days)
	}
	return n
}
