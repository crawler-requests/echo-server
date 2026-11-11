package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Console-side operational data lives in the same SQLite file as the echo
// config. All tables are created lazily so upgrades need no migration step.
var extraOnce sync.Once

func initExtraDB() {
	extraOnce.Do(func() {
		initDB()
		stmts := []string{
			`CREATE TABLE IF NOT EXISTS audit_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ts TEXT NOT NULL,
				username TEXT NOT NULL DEFAULT '',
				action TEXT NOT NULL,
				target TEXT NOT NULL DEFAULT '',
				detail TEXT NOT NULL DEFAULT '',
				ip TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)`,
			`CREATE TABLE IF NOT EXISTS api_keys (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL UNIQUE,
				key_hash TEXT NOT NULL,
				prefix TEXT NOT NULL,
				scope TEXT NOT NULL DEFAULT 'viewer',
				enabled INTEGER NOT NULL DEFAULT 1,
				created_at TEXT NOT NULL,
				last_used TEXT NOT NULL DEFAULT '',
				expires_at TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE TABLE IF NOT EXISTS webhooks (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL UNIQUE,
				url TEXT NOT NULL,
				secret TEXT NOT NULL DEFAULT '',
				events TEXT NOT NULL DEFAULT '',
				enabled INTEGER NOT NULL DEFAULT 1,
				created_at TEXT NOT NULL,
				last_status TEXT NOT NULL DEFAULT '',
				last_sent TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE TABLE IF NOT EXISTS notifications (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ts TEXT NOT NULL,
				level TEXT NOT NULL DEFAULT 'info',
				title TEXT NOT NULL,
				body TEXT NOT NULL DEFAULT '',
				source TEXT NOT NULL DEFAULT 'system',
				read INTEGER NOT NULL DEFAULT 0
			)`,
			`CREATE TABLE IF NOT EXISTS saved_views (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL,
				page TEXT NOT NULL,
				filters TEXT NOT NULL DEFAULT '{}',
				username TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL,
				UNIQUE(page, name)
			)`,
		}
		for _, s := range stmts {
			_, _ = db.Exec(s)
		}
	})
}

// AuditEntry is one recorded write operation.
type AuditEntry struct {
	ID       int64  `json:"id"`
	TS       string `json:"ts"`
	Username string `json:"username"`
	Action   string `json:"action"`
	Target   string `json:"target"`
	Detail   string `json:"detail"`
	IP       string `json:"ip"`
}

// Notify inserts a console notification.
func Notify(level, title, body, source string) {
	initExtraDB()
	if len(body) > 4000 {
		body = body[:4000]
	}
	_, _ = db.Exec(`INSERT INTO notifications(ts, level, title, body, source) VALUES(?,?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339), level, title, body, source)
}

// RecordAudit stores one audit entry and optionally raises a notification.
func RecordAudit(r *http.Request, action, target, detail string) {
	initExtraDB()
	user := "-"
	ip := "-"
	if r != nil {
		if u := currentUser(r); u != nil {
			user = u.Username
		}
		ip = extractClientIP(r)
	}
	_, _ = db.Exec(`INSERT INTO audit_log(ts, username, action, target, detail, ip) VALUES(?,?,?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339), user, action, target, detail, ip)
	if strings.HasPrefix(action, "user.") || strings.HasPrefix(action, "security.") ||
		strings.HasPrefix(action, "config.") || strings.HasPrefix(action, "system.") {
		level := "info"
		if strings.Contains(action, "delete") || strings.Contains(action, "rotate") || strings.Contains(action, "purge") {
			level = "warning"
		}
		Notify(level, auditTitle(action), target+" "+detail, "audit")
	}
}

func auditTitle(action string) string {
	switch action {
	case "config.update":
		return "配置已更新"
	case "user.create":
		return "新账号已创建"
	case "user.update":
		return "账号已修改"
	case "user.delete":
		return "账号已删除"
	case "security.rotate_jwt":
		return "已轮换会话签名密钥"
	case "system.purge_logs":
		return "查询日志已清理"
	case "system.backup":
		return "数据库备份已导出"
	case "apikey.create":
		return "API Key 已创建"
	case "apikey.delete":
		return "API Key 已删除"
	case "webhook.test":
		return "Webhook 测试已发送"
	}
	return "系统事件：" + action
}

func auditCSV(w http.ResponseWriter, rows []AuditEntry) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-log.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "ts", "username", "action", "target", "detail", "ip"})
	for _, e := range rows {
		_ = cw.Write([]string{strconv.FormatInt(e.ID, 10), e.TS, e.Username, e.Action, e.Target, e.Detail, e.IP})
	}
	cw.Flush()
}

// auditHandler serves the audit trail: JSON by default, CSV with ?format=csv.
func auditHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	initExtraDB()
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
			if limit > 2000 {
				limit = 2000
			}
		}
	}
	q := `SELECT id, ts, username, action, target, detail, ip FROM audit_log`
	var args []any
	var where []string
	if v := strings.TrimSpace(r.URL.Query().Get("action")); v != "" {
		where = append(where, "action LIKE ?")
		args = append(args, v+"%")
	}
	if v := strings.TrimSpace(r.URL.Query().Get("username")); v != "" {
		where = append(where, "username = ?")
		args = append(args, strings.ToLower(v))
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := db.Query(q, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Username, &e.Action, &e.Target, &e.Detail, &e.IP); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, e)
	}
	if r.URL.Query().Get("format") == "csv" || strings.HasSuffix(r.URL.Path, ".csv") {
		auditCSV(w, out)
		return
	}
	writeJSON(w, out)
}

// notificationHandler manages the bell list.
//
//	GET    /api/notifications?limit=&unread=1
//	POST   /api/notifications   {id} / {all:true}
//	DELETE /api/notifications   clears read entries (or all with ?all=1)
func notificationHandler(w http.ResponseWriter, r *http.Request) {
	initExtraDB()
	switch r.Method {
	case http.MethodGet:
		limit := 50
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = min(n, 500)
			}
		}
		q := `SELECT id, ts, level, title, body, source, read FROM notifications`
		if r.URL.Query().Get("unread") == "1" {
			q += ` WHERE read = 0`
		}
		q += ` ORDER BY id DESC LIMIT ?`
		rows, err := db.Query(q, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id int64
			var ts, level, title, body, source string
			var read int
			if err := rows.Scan(&id, &ts, &level, &title, &body, &source, &read); err != nil {
				continue
			}
			out = append(out, map[string]any{
				"id": id, "ts": ts, "level": level, "title": title,
				"body": body, "source": source, "read": read != 0,
			})
		}
		var unread int
		_ = db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE read = 0`).Scan(&unread)
		writeJSON(w, map[string]any{"items": out, "unread": unread})
	case http.MethodPost:
		var req struct {
			ID  int64 `json:"id"`
			All bool  `json:"all"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.All {
			_, _ = db.Exec(`UPDATE notifications SET read = 1 WHERE read = 0`)
		} else if req.ID > 0 {
			_, _ = db.Exec(`UPDATE notifications SET read = 1 WHERE id = ?`, req.ID)
		}
		writeJSON(w, map[string]string{"status": "ok"})
	case http.MethodDelete:
		if r.URL.Query().Get("all") == "1" {
			_, _ = db.Exec(`DELETE FROM notifications`)
		} else {
			_, _ = db.Exec(`DELETE FROM notifications WHERE read = 1`)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// savedViewHandler stores named filter presets for the console pages.
func savedViewHandler(w http.ResponseWriter, r *http.Request) {
	initExtraDB()
	switch r.Method {
	case http.MethodGet:
		page := r.URL.Query().Get("page")
		q := `SELECT id, name, page, filters, username, created_at FROM saved_views`
		var args []any
		if page != "" {
			q += ` WHERE page = ?`
			args = append(args, page)
		}
		q += ` ORDER BY id DESC`
		rows, err := db.Query(q, args...)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id int64
			var name, pg, filters, user, created string
			if rows.Scan(&id, &name, &pg, &filters, &user, &created) == nil {
				out = append(out, map[string]any{"id": id, "name": name, "page": pg, "filters": filters, "username": user, "created_at": created})
			}
		}
		writeJSON(w, out)
	case http.MethodPost:
		var req struct {
			Name    string `json:"name"`
			Page    string `json:"page"`
			Filters string `json:"filters"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" || req.Page == "" {
			http.Error(w, "name and page are required", http.StatusBadRequest)
			return
		}
		if req.Filters == "" {
			req.Filters = "{}"
		}
		user := ""
		if u := currentUser(r); u != nil {
			user = u.Username
		}
		_, err := db.Exec(`INSERT OR REPLACE INTO saved_views(name, page, filters, username, created_at) VALUES(?,?,?,?,?)`,
			req.Name, req.Page, req.Filters, user, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	case http.MethodDelete:
		id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		_, err := db.Exec(`DELETE FROM saved_views WHERE id = ?`, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

var errNoRows = errors.New("no rows")
