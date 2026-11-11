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
func allowRate(ip string) bool {
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
	b := rateState.buckets[ip]
	if b == nil || now.After(b.reset) {
		rateState.buckets[ip] = &rateBucket{count: 1, reset: now.Add(time.Minute)}
		return true
	}
	if b.count >= limit {
		return false
	}
	b.count++
	return true
}

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
			if !allowRate(ip) {
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
