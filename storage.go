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
		home, _ := os.UserHomeDir()
		dir := filepath.Join(home, ".echo-server")
		_ = os.MkdirAll(dir, 0700)
		dbPath = filepath.Join(dir, "echo.db")
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
