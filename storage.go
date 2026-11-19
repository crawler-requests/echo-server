package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

var (
	db     *sql.DB
	dbOnce sync.Once
	dbPath string
	// liteMode disables the database entirely (ECHO_SERVER_LITE=1). GetConfig
	// then answers from an empty cache and LogQuery* becomes a no-op, so the
	// request path never touches disk.
	liteMode bool
)

// initDB opens (or creates) the SQLite database in ~/.echo-server/echo.db.
// In lite mode it is a no-op: the server runs without any database.
func initDB() error {
	if liteMode || os.Getenv("ECHO_SERVER_LITE") == "1" {
		liteMode = true
		return nil
	}
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
		// SQLite (modernc) allows one writer at a time; a WAL journal lets
		// readers proceed while a writer commits, which is what keeps the
		// console usable during a log burst. busy_timeout makes a writer wait
		// for the lock instead of failing the statement outright.
		db, err = sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
		if err != nil {
			return
		}
		// One writer + a small read pool. Unbounded connections against SQLite
		// just queue on the file lock and waste goroutines.
		db.SetMaxOpenConns(8)
		db.SetMaxIdleConns(8)
		db.SetConnMaxLifetime(0)
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
				country TEXT,
				-- Client identification is computed for every echo request, but
				-- used to be thrown away: only the in-memory response carried it.
				-- Persisting the verdict makes the console able to answer "which
				-- clients hit us", "how many UA spoofs", and "which fingerprints
				-- are unknown" — the core questions this service exists for.
				client_name TEXT NOT NULL DEFAULT '',
				client_family TEXT NOT NULL DEFAULT '',
				client_source TEXT NOT NULL DEFAULT '',
				ja4 TEXT NOT NULL DEFAULT '',
				ja3 TEXT NOT NULL DEFAULT '',
				user_agent TEXT NOT NULL DEFAULT '',
				spoofed INTEGER NOT NULL DEFAULT 0
			);`)
		if err != nil {
			return
		}
		// Existing databases predate the client columns: add them in place.
		// ALTER TABLE ADD COLUMN is cheap and idempotent here because the
		// error for an already-present column is ignored.
		for _, col := range []struct{ name, typ, def string }{
			{"client_name", "TEXT", "''"},
			{"client_family", "TEXT", "''"},
			{"client_source", "TEXT", "''"},
			{"ja4", "TEXT", "''"},
			{"ja3", "TEXT", "''"},
			{"user_agent", "TEXT", "''"},
			{"spoofed", "INTEGER", "0"},
		} {
			_, _ = db.Exec(`ALTER TABLE query_log ADD COLUMN ` + col.name + ` ` + col.typ + ` NOT NULL DEFAULT ` + col.def)
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
		if err != nil {
			return
		}
		// query_log is the hottest table: every echo request inserts a row and
		// the console filters by time, IP, and connection type. The indexes
		// match the query shapes in export.go / metrics.go / ip_lookup_api.go.
		// ts is ISO-8601 UTC so plain string comparison is chronological.
		for _, stmt := range []string{
			`CREATE INDEX IF NOT EXISTS idx_query_log_ts ON query_log(ts)`,
			`CREATE INDEX IF NOT EXISTS idx_query_log_ip ON query_log(ip)`,
			`CREATE INDEX IF NOT EXISTS idx_query_log_conn_country ON query_log(connection_type, country)`,
			// Client-identification filters and aggregations.
			`CREATE INDEX IF NOT EXISTS idx_query_log_client ON query_log(client_name, client_family)`,
			`CREATE INDEX IF NOT EXISTS idx_query_log_ja4 ON query_log(ja4)`,
			`CREATE INDEX IF NOT EXISTS idx_query_log_spoofed ON query_log(spoofed, ts)`,
			// Retention purge deletes by ts; the ts index already covers it.
		} {
			_, _ = db.Exec(stmt)
		}
	})
	return err
}

// GetConfig reads a config value (returns "" if missing)
// configCache memoises the whole config table in memory.
//
// GetConfig is on every request path (the echo handler alone reads ~15 keys)
// and a SQLite round trip costs ~14 µs, i.e. ~200 µs of pure query overhead per
// request. That is the throughput ceiling long before CPU or network are: at
// 1000 rps it is 200 ms of database time every second, all serialised through
// one connection pool. The table is small (dozens of rows) and written only by
// SetConfig, so caching it wholesale is both simpler and faster than per-key
// lookups, and SetConfig invalidates it.
var configCache = struct {
	sync.RWMutex
	loaded bool
	m      map[string]string
}{}

// loadConfigLocked refreshes the cache. Callers hold the write lock.
func loadConfigLocked() error {
	initDB()
	rows, err := db.Query(`SELECT key, value FROM config`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := make(map[string]string, 128)
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			m[k] = v
		}
	}
	configCache.m = m
	configCache.loaded = true
	return rows.Err()
}

// GetConfig reads a config value (returns "" if missing). Values come from the
// in-memory cache, which SetConfig keeps current.
func GetConfig(key string) string {
	// Lite mode has no database: every key falls back to its default, which is
	// exactly what the fast path wants (no geolocation, no toggles to honour).
	if liteMode || os.Getenv("ECHO_SERVER_LITE") == "1" {
		liteMode = true
		return ""
	}
	configCache.RLock()
	if configCache.loaded {
		v := configCache.m[key]
		configCache.RUnlock()
		return v
	}
	configCache.RUnlock()

	configCache.Lock()
	defer configCache.Unlock()
	if !configCache.loaded {
		if err := loadConfigLocked(); err != nil {
			// A broken read still has to answer: fall back to one direct query
			// so a transient DB error does not look like "config is empty".
			var v string
			_ = db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&v)
			return v
		}
	}
	return configCache.m[key]
}

// SetConfig writes a config key/value and refreshes the cache, so the next
// GetConfig sees the new value immediately (the console expects that).
func SetConfig(key, value string) error {
	initDB()
	_, err := db.Exec(`INSERT OR REPLACE INTO config(key, value) VALUES(?, ?)`, key, value)
	if err != nil {
		return err
	}
	configCache.Lock()
	if configCache.loaded {
		configCache.m[key] = value
	}
	configCache.Unlock()
	return nil
}

// invalidateConfigCache forces the next GetConfig to re-read the table. Used by
// tests that write the config table directly, and as a safety hatch.
func invalidateConfigCache() {
	configCache.Lock()
	configCache.loaded = false
	configCache.m = nil
	configCache.Unlock()
}

// LogQuery inserts a query record with the connection classification.
// Client identification is attached separately by LogQueryDetailed so existing
// callers and tests keep this simple form.
func LogQuery(method, path, ip, connType, country string) {
	LogQueryDetailed(queryRecord{
		Method: method, Path: path, IP: ip,
		ConnectionType: connType, Country: country,
	})
}

// queryRecord is the full row written for one /echo request.
type queryRecord struct {
	Method         string
	Path           string
	IP             string
	ConnectionType string
	Country        string
	ClientName     string
	ClientFamily   string
	ClientSource   string
	JA4            string
	JA3            string
	UserAgent      string
	Spoofed        bool
}

// Query-log write batching.
//
// Every /echo request produces one INSERT. Writing it synchronously ties a
// request's latency to a disk commit and serialises all writers through
// SQLite's single writer, which caps throughput far below what the CPU or
// network can do. Instead the records are queued and written in batches:
// the request path only appends to a channel (non-blocking until the queue is
// full), and one goroutine commits up to logBatchSize rows in one transaction.
//
// Trade-offs are deliberate and small:
//   - a row can be lost if the process dies within the batch window (≤~250 ms);
//     the query log is triage data, not an audit trail (that is audit_log,
//     which stays synchronous),
//   - the log lags by at most one batch.
const (
	logBatchSize = 256
	logQueueSize = 8192
)

var queryLogQueue = make(chan queryRecord, logQueueSize)

var queryLogWriter = struct {
	once sync.Once
}{}

// startQueryLogWriter launches the single batch writer (idempotent).
func startQueryLogWriter() {
	queryLogWriter.once.Do(func() {
		go func() {
			initDB()
			buf := make([]queryRecord, 0, logBatchSize)
			flush := func() {
				if len(buf) == 0 {
					return
				}
				flushQueryLog(buf)
				buf = buf[:0]
			}
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case rec, ok := <-queryLogQueue:
					if !ok {
						flush()
						return
					}
					buf = append(buf, rec)
					if len(buf) >= logBatchSize {
						flush()
					}
				case <-ticker.C:
					flush()
				case ack := <-logDrainRequest:
					// Drain whatever is queued, then acknowledge: a caller
					// waiting on FlushQueryLog must see every record written
					// before it issued the request.
					for {
						select {
						case rec := <-queryLogQueue:
							buf = append(buf, rec)
							if len(buf) >= logBatchSize {
								flush()
							}
							continue
						default:
						}
						break
					}
					flush()
					close(ack)
				}
			}
		}()
	})
}

// flushQueryLog writes one batch in a single transaction.
func flushQueryLog(batch []queryRecord) {
	initDB()
	tx, err := db.Begin()
	if err != nil {
		return
	}
	stmt, err := tx.Prepare(`INSERT INTO query_log(
		ts, method, path, ip, connection_type, country,
		client_name, client_family, client_source, ja4, ja3, user_agent, spoofed
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return
	}
	defer stmt.Close()
	for _, rec := range batch {
		ua := rec.UserAgent
		if len(ua) > 200 {
			ua = ua[:200]
		}
		spoofed := 0
		if rec.Spoofed {
			spoofed = 1
		}
		if _, err := stmt.Exec(
			time.Now().UTC().Format(time.RFC3339), rec.Method, rec.Path, rec.IP,
			rec.ConnectionType, rec.Country, rec.ClientName, rec.ClientFamily,
			rec.ClientSource, rec.JA4, rec.JA3, ua, spoofed,
		); err != nil {
			_ = tx.Rollback()
			return
		}
	}
	_ = tx.Commit()
}

// LogQueryDetailed queues the request plus its client-identification verdict.
// It never blocks the request path: when the queue is full (a stalled disk)
// the record is dropped and counted, rather than adding latency to the request.
// The UA is truncated: the log is for triage, not archival.
func LogQueryDetailed(rec queryRecord) {
	if liteMode || os.Getenv("ECHO_SERVER_LITE") == "1" {
		liteMode = true
		return
	}
	startQueryLogWriter()
	select {
	case queryLogQueue <- rec:
	default:
		droppedLogRecords.Add(1)
	}
}

// logDrainRequest asks the writer goroutine to flush what it holds and
// acknowledge; draining from here (rather than reading the channel ourselves)
// is what guarantees the writer's in-memory buffer is not lost.
var logDrainRequest = make(chan chan struct{}, 4)

// FlushQueryLog waits until every queued record has been committed. It is
// used by tests (so assertions see their rows immediately) and by the
// graceful-shutdown path.
func FlushQueryLog() {
	startQueryLogWriter()
	// Keep asking until the queue is empty and the writer acknowledges: new
	// records may arrive while we wait.
	for {
		ack := make(chan struct{})
		logDrainRequest <- ack
		<-ack
		if len(queryLogQueue) == 0 {
			return
		}
	}
}

// writeQueryLogSync writes one row immediately, bypassing the queue. Used by
// callers that need the row visible before returning (the console's own view
// is read-after-write only for its own actions, which are rare).
func writeQueryLogSync(rec queryRecord) {
	flushQueryLog([]queryRecord{rec})
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

// droppedLogRecords counts query-log rows refused because the queue was full.
var droppedLogRecords atomic.Uint64
