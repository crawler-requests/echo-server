package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	db     *sql.DB
	dbOnce sync.Once
	dbPath string
)

// initDB opens (or creates) the SQLite database in ~/.echo-server/echo.db
func initDB() error {
	var err error
	dbOnce.Do(func() {
		// ECHO_SERVER_DB lets tests (and side-by-side deployments) point at an
		// isolated database instead of the user's ~/.echo-server/echo.db.
		dbPath = os.Getenv("ECHO_SERVER_DB")
		if dbPath == "" {
			home, _ := os.UserHomeDir()
			dir := filepath.Join(home, ".echo-server")
			_ = os.MkdirAll(dir, 0700)
			dbPath = filepath.Join(dir, "echo.db")
		}
		if dir := filepath.Dir(dbPath); dir != "" {
			_ = os.MkdirAll(dir, 0700)
		}
		db, err = sql.Open("sqlite", dbPath)
		if err != nil {
			return
		}
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT
		);`)
		if err != nil {
			return
		}
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS query_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT,
			method TEXT,
			path TEXT,
			ip TEXT,
			connection_type TEXT,
			country TEXT
		);`)
		if err != nil {
			return
		}
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'viewer',
			disabled INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_login TEXT NOT NULL DEFAULT ''
		);`)
	})
	return err
}

// GetConfig reads a config value (returns "" if missing)
func GetConfig(key string) string {
	initDB()
	var v string
	_ = db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&v)
	return v
}

// SetConfig writes a config key/value
func SetConfig(key, value string) error {
	initDB()
	_, err := db.Exec(`INSERT OR REPLACE INTO config(key, value) VALUES(?, ?)`, key, value)
	return err
}

// LogQuery inserts a minimal query record
func LogQuery(method, path, ip, connType, country string) {
	initDB()
	_, _ = db.Exec(`INSERT INTO query_log(ts, method, path, ip, connection_type, country) VALUES(?,?,?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339), method, path, ip, connType, country)
}

// QueryStats is the small aggregate shown on the console dashboard.
type QueryStats struct {
	Users        int `json:"users"`
	QueriesTotal int `json:"queries_total"`
	QueriesToday int `json:"queries_today"`
}

// GetStats returns account and query-log totals. Counting in SQLite keeps the
// dashboard cheap even when the log table has grown large.
func GetStats() QueryStats {
	initDB()
	var s QueryStats
	_ = db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&s.Users)
	_ = db.QueryRow(`SELECT COUNT(*) FROM query_log`).Scan(&s.QueriesTotal)
	today := time.Now().UTC().Format("2006-01-02") + "T00:00:00Z"
	_ = db.QueryRow(`SELECT COUNT(*) FROM query_log WHERE ts >= ?`, today).Scan(&s.QueriesToday)
	return s
}

// GetRecentLogs returns the last N query records (for admin UI)
func GetRecentLogs(limit int) []map[string]string {
	initDB()
	rows, err := db.Query(`SELECT ts, method, path, ip, connection_type, country FROM query_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var ts, m, p, ip, ct, c string
		rows.Scan(&ts, &m, &p, &ip, &ct, &c)
		out = append(out, map[string]string{"ts": ts, "method": m, "path": p, "ip": ip, "connection_type": ct, "country": c})
	}
	return out
}
