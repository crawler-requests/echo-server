package main

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type logFilter struct {
	Limit     int
	Method    string
	Country   string
	ConnType  string
	IP        string
	Query     string
	SinceDays int
}

func parseLogFilter(r *http.Request) logFilter {
	f := logFilter{Limit: 200}
	q := r.URL.Query()
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		f.Limit = n
		if f.Limit > 10000 {
			f.Limit = 10000
		}
	}
	f.Method = strings.ToUpper(strings.TrimSpace(q.Get("method")))
	f.Country = strings.TrimSpace(q.Get("country"))
	f.ConnType = strings.TrimSpace(q.Get("type"))
	f.IP = strings.TrimSpace(q.Get("ip"))
	f.Query = strings.TrimSpace(q.Get("q"))
	if n, err := strconv.Atoi(q.Get("days")); err == nil && n > 0 {
		f.SinceDays = n
	}
	return f
}

// fetchLogs applies the shared filters used by the log page and exports.
func fetchLogs(f logFilter) []map[string]string {
	initDB()
	sql := `SELECT ts, method, path, ip, connection_type, country FROM query_log`
	var where []string
	var args []any
	if f.Method != "" {
		where = append(where, "UPPER(method) = ?")
		args = append(args, f.Method)
	}
	if f.Country != "" {
		where = append(where, "country = ?")
		args = append(args, f.Country)
	}
	if f.ConnType != "" {
		where = append(where, "connection_type = ?")
		args = append(args, f.ConnType)
	}
	if f.IP != "" {
		where = append(where, "ip = ?")
		args = append(args, f.IP)
	}
	if f.Query != "" {
		where = append(where, "(path LIKE ? OR ip LIKE ? OR country LIKE ?)")
		like := "%" + f.Query + "%"
		args = append(args, like, like, like)
	}
	if f.SinceDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -f.SinceDays).Format(time.RFC3339)
		where = append(where, "ts >= ?")
		args = append(args, cutoff)
	}
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY id DESC LIMIT ?"
	args = append(args, f.Limit)
	rows, err := db.Query(sql, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var ts, m, p, ip, ct, c string
		if rows.Scan(&ts, &m, &p, &ip, &ct, &c) == nil {
			out = append(out, map[string]string{"ts": ts, "method": m, "path": p, "ip": ip, "connection_type": ct, "country": c})
		}
	}
	return out
}

// logsCSVHandler exports the (filtered) query log as CSV or JSON.
func logsExportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rows := fetchLogs(parseLogFilter(r))
	if strings.HasSuffix(r.URL.Path, ".json") {
		w.Header().Set("Content-Disposition", `attachment; filename="query-logs.json"`)
		writeJSON(w, rows)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="query-logs.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ts", "method", "path", "ip", "connection_type", "country"})
	for _, row := range rows {
		_ = cw.Write([]string{row["ts"], row["method"], row["path"], row["ip"], row["connection_type"], row["country"]})
	}
	cw.Flush()
}

// usersExportHandler dumps accounts (without password hashes).
func usersExportHandler(w http.ResponseWriter, r *http.Request) {
	users, err := ListUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if strings.HasSuffix(r.URL.Path, ".json") {
		w.Header().Set("Content-Disposition", `attachment; filename="users.json"`)
		writeJSON(w, users)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="users.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "username", "role", "disabled", "created_at", "last_login"})
	for _, u := range users {
		_ = cw.Write([]string{
			strconv.FormatInt(u.ID, 10), u.Username, u.Role, strconv.FormatBool(u.Disabled), u.CreatedAt, u.LastLogin,
		})
	}
	cw.Flush()
}

// configExportHandler downloads every config key that is safe to move between
// instances. Secrets (JWT signing key, tokens) are deliberately omitted.
func configExportHandler(w http.ResponseWriter, r *http.Request) {
	initDB()
	rows, err := db.Query(`SELECT key, value FROM config ORDER BY key`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := map[string]string{}
	skip := map[string]bool{"jwt_secret": true, "ipinfo_token": true, "api_token": true}
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil && !skip[k] {
			out[k] = v
		}
	}
	w.Header().Set("Content-Disposition", `attachment; filename="echo-config.json"`)
	writeJSON(w, out)
}

// replayHandler runs a synthetic request through echoHandler and returns the
// exact payload the endpoint would have produced. It is a debugging aid, so
// it is admin-only and capped at 256 KiB of request body.
func replayHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Method  string            `json:"method"`
		Path    string            `json:"path"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	if req.Path == "" || !strings.HasPrefix(req.Path, "/") {
		http.Error(w, "path must start with /", http.StatusBadRequest)
		return
	}
	result := replayEcho(req.Method, req.Path, req.Headers, req.Body)
	writeJSON(w, result)
}
