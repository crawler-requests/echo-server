package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// These are overridden at release time via -ldflags "-X main.serverVersion=...".
// A source checkout reports "dev"; release binaries always carry the tag value.
var (
	serverVersion = "dev"
	buildCommit   = ""
	buildDate     = ""
)

var serverStarted = time.Now()

// systemHandler reports build/runtime facts and the active listener setup.
func systemHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	initDB()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	dbSize := int64(0)
	if st, err := os.Stat(dbPath); err == nil {
		dbSize = st.Size()
	}
	httpsPort := os.Getenv("PORT")
	if httpsPort == "" {
		httpsPort = "8443"
	}
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8080"
	}
	writeJSON(w, map[string]any{
		"version":        serverVersion,
		"build_commit":   buildCommit,
		"build_date":     buildDate,
		"go_version":     runtime.Version(),
		"os":             runtime.GOOS,
		"arch":           runtime.GOARCH,
		"cpus":           runtime.NumCPU(),
		"started_at":     serverStarted.UTC().Format(time.RFC3339),
		"uptime_seconds": int64(time.Since(serverStarted).Seconds()),
		"goroutines":     runtime.NumGoroutine(),
		"memory_alloc":   mem.Alloc,
		"memory_sys":     mem.Sys,
		"gc_cycles":      mem.NumGC,
		"db_path":        dbPath,
		"db_size":        dbSize,
		"https_port":     httpsPort,
		"http_port":      httpPort,
		"maintenance":    GetConfig("maintenance_mode") == "true",
		"jwt_secret_env": jwtSecretFromEnv,
		"stats":          GetStats(),
	})
}

// purgeLogsHandler deletes query history. POST {"days":N} keeps the last N
// days; {"all":true} empties the table.
func purgeLogsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Days int  `json:"days"`
		All  bool `json:"all"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var res interface {
		RowsAffected() (int64, error)
	}
	var err error
	switch {
	case req.All:
		res, err = db.Exec(`DELETE FROM query_log`)
	case req.Days > 0:
		cutoff := time.Now().UTC().AddDate(0, 0, -req.Days).Format(time.RFC3339)
		res, err = db.Exec(`DELETE FROM query_log WHERE ts < ?`, cutoff)
	default:
		http.Error(w, "days>0 or all=true is required", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	deleted, _ := res.RowsAffected()
	detail := "all"
	if !req.All {
		detail = strconv.Itoa(req.Days) + "d"
	}
	RecordAudit(r, "system.purge_logs", detail, "deleted="+strconv.FormatInt(deleted, 10))
	writeJSON(w, map[string]any{"status": "ok", "deleted": deleted})
}

// rotateJWTHandler invalidates all sessions; the caller gets a fresh token.
func rotateJWTHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := rotateJWTSecret(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	u := currentUser(r)
	tok := ""
	if u != nil {
		tok, _ = generateTokenFor(u)
	}
	RecordAudit(r, "security.rotate_jwt", "", "all sessions invalidated")
	emitEvent("security.alert", map[string]any{
		"actor":  userName(r),
		"action": "rotate_jwt",
		"detail": "所有登录会话已失效",
	})
	writeJSON(w, map[string]any{"status": "ok", "token": tok})
}

// backupHandler produces a consistent snapshot with VACUUM INTO and streams
// it to the admin as a download.
func backupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	initDB()
	f, err := os.CreateTemp("", "echo-backup-*.db")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := f.Name()
	f.Close()
	_ = os.Remove(name)
	defer os.Remove(name)
	if _, err := db.Exec(`VACUUM INTO ?`, name); err != nil {
		http.Error(w, "backup failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	f, err = os.Open(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	filename := "echo-server-backup-" + time.Now().Format("20060102-150405") + ".db"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	RecordAudit(r, "system.backup", filename, "")
	http.ServeContent(w, r, filename, st.ModTime(), f)
}

func userName(r *http.Request) string {
	if u := currentUser(r); u != nil {
		return u.Username
	}
	return "-"
}

// environmentHandler exposes non-secret operator-facing environment values.
func environmentHandler(w http.ResponseWriter, r *http.Request) {
	keys := []string{
		"show_ja3", "show_ip", "show_raw", "show_body", "show_client", "show_ja4h",
		"require_token", "allow_registration", "enable_online_geo", "geo_provider",
		"geo_cache_ttl", "default_format", "maintenance_mode", "maintenance_message",
		"ip_allowlist", "ip_denylist", "rate_limit_per_min", "cors_origins",
		"security_headers", "body_limit_kb", "log_retention_days",
		"site_name", "site_description", "timezone", "locale", "density",
	}
	out := map[string]string{}
	for _, k := range keys {
		out[k] = GetConfig(k)
	}
	out["db_path"] = dbPath
	if env := os.Getenv("ECHO_SERVER_DB"); env != "" {
		out["db_path_source"] = "ECHO_SERVER_DB"
	} else {
		out["db_path_source"] = "default"
	}
	if _, err := os.Stat(filepath.Dir(dbPath)); err == nil {
		out["db_dir"] = filepath.Dir(dbPath)
	}
	if strings.TrimSpace(out["site_name"]) == "" {
		out["site_name"] = "Echo Server"
	}
	writeJSON(w, out)
}
