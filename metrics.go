package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"
)

type countRow struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

// metricsSummaryHandler aggregates query_log by hour and by the dimensions the
// console charts need. ?hours=N (1..720, default 24).
func metricsSummaryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	initDB()
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			hours = n
			if hours > 720 {
				hours = 720
			}
		}
	}
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Truncate(time.Hour)
	sinceStr := since.Format(time.RFC3339)

	var total, uniqueIPs int
	_ = db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT ip) FROM query_log WHERE ts >= ?`, sinceStr).Scan(&total, &uniqueIPs)

	hourCounts := map[string]int{}
	if rows, err := db.Query(`SELECT strftime('%Y-%m-%dT%H:00:00Z', ts) AS h, COUNT(*) FROM query_log WHERE ts >= ? GROUP BY h ORDER BY h`, sinceStr); err == nil {
		for rows.Next() {
			var h string
			var n int
			if rows.Scan(&h, &n) == nil {
				hourCounts[h] = n
			}
		}
		rows.Close()
	}
	byHour := make([]map[string]any, 0, hours+1)
	for t := since; !t.After(time.Now().UTC()); t = t.Add(time.Hour) {
		key := t.Format(time.RFC3339)
		byHour = append(byHour, map[string]any{"hour": key, "count": hourCounts[key]})
	}

	group := func(column string, limit int) []countRow {
		out := []countRow{}
		q := `SELECT COALESCE(NULLIF(` + column + `,''),'unknown') AS k, COUNT(*) AS n
			FROM query_log WHERE ts >= ? GROUP BY k ORDER BY n DESC LIMIT ?`
		rows, err := db.Query(q, sinceStr, limit)
		if err != nil {
			return out
		}
		defer rows.Close()
		for rows.Next() {
			var c countRow
			if rows.Scan(&c.Label, &c.Count) == nil {
				out = append(out, c)
			}
		}
		return out
	}

	writeJSON(w, map[string]any{
		"hours":         hours,
		"since":         sinceStr,
		"total":         total,
		"unique_ips":    uniqueIPs,
		"by_hour":       byHour,
		"top_ips":       group("ip", 8),
		"top_countries": group("country", 8),
		"top_methods":   group("method", 8),
		"by_connection": group("connection_type", 8),
	})
}

// prometheusHandler exposes the same counters in Prometheus text format so
// the service can be scraped without an exporter.
func prometheusHandler(w http.ResponseWriter, r *http.Request) {
	initDB()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	s := GetStats()
	var apiKeys, webhooks, unread int
	initExtraDB()
	_ = db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE enabled = 1`).Scan(&apiKeys)
	_ = db.QueryRow(`SELECT COUNT(*) FROM webhooks WHERE enabled = 1`).Scan(&webhooks)
	_ = db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE read = 0`).Scan(&unread)
	dbSize := int64(0)
	if st, err := os.Stat(dbPath); err == nil {
		dbSize = st.Size()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	lines := []struct {
		name, help, typ string
		value           int64
	}{
		{"echo_queries_total", "Total echo requests recorded", "counter", int64(s.QueriesTotal)},
		{"echo_queries_today", "Echo requests recorded today (UTC)", "gauge", int64(s.QueriesToday)},
		{"echo_users_total", "Accounts on this instance", "gauge", int64(s.Users)},
		{"echo_uptime_seconds", "Seconds since the process started", "gauge", int64(time.Since(serverStarted).Seconds())},
		{"echo_go_goroutines", "Active goroutines", "gauge", int64(runtime.NumGoroutine())},
		{"echo_memory_alloc_bytes", "Allocated Go heap bytes", "gauge", int64(mem.Alloc)},
		{"echo_memory_sys_bytes", "Go runtime reserved bytes", "gauge", int64(mem.Sys)},
		{"echo_db_size_bytes", "SQLite database size", "gauge", dbSize},
		{"echo_api_keys_enabled", "Enabled API keys", "gauge", int64(apiKeys)},
		{"echo_webhooks_enabled", "Enabled webhooks", "gauge", int64(webhooks)},
		{"echo_notifications_unread", "Unread console notifications", "gauge", int64(unread)},
	}
	for _, l := range lines {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", l.name, l.help, l.name, l.typ, l.name, l.value)
	}
}
