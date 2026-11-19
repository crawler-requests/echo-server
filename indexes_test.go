package main

import (
	"strings"
	"testing"
)

// The console filters query_log by time, IP, connection type and country, and
// the audit trail by actor and action. Those lookups must be index-backed; a
// missing index turns a sub-millisecond lookup into a full table scan once the
// table grows.
func TestQueryLogIndexes(t *testing.T) {
	initDB()
	initExtraDB()

	wanted := []struct {
		table, index string
	}{
		{"query_log", "idx_query_log_ts"},
		{"query_log", "idx_query_log_ip"},
		{"query_log", "idx_query_log_conn_country"},
		{"query_log", "idx_query_log_client"},
		{"query_log", "idx_query_log_ja4"},
		{"query_log", "idx_query_log_spoofed"},
		{"audit_log", "idx_audit_ts"},
		{"audit_log", "idx_audit_username"},
		{"audit_log", "idx_audit_action"},
		{"notifications", "idx_notifications_read_ts"},
		{"api_keys", "idx_api_keys_hash"},
		{"webhooks", "idx_webhooks_enabled"},
		{"saved_views", "idx_saved_views_page"},
	}
	for _, w := range wanted {
		var name string
		err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=? AND name=?`,
			w.table, w.index).Scan(&name)
		if err != nil {
			t.Errorf("index %s on %s missing: %v", w.index, w.table, err)
		}
	}
}

// The query planner must actually choose the index for the filter shapes the
// API issues; an index that exists but is unusable is just disk overhead.
func TestQueryLogIndexesAreUsed(t *testing.T) {
	initDB()
	cases := []struct {
		name, query, wantIndex string
	}{
		{"by ip", `SELECT ts FROM query_log WHERE ip = '8.8.8.8' ORDER BY id DESC LIMIT 50`, "idx_query_log_ip"},
		{"by connection type", `SELECT COUNT(*) FROM query_log WHERE connection_type = 'datacenter'`, "idx_query_log_conn_country"},
		{"audit by actor", `SELECT id FROM audit_log WHERE username = 'bob'`, "idx_audit_username"},
		{"unread notifications", `SELECT id FROM notifications WHERE read = 0`, "idx_notifications_read_ts"},
	}
	for _, c := range cases {
		rows, err := db.Query("EXPLAIN QUERY PLAN " + c.query)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		var plan []string
		for rows.Next() {
			var id, parent, notUsed int
			var detail string
			if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
				t.Fatalf("%s scan: %v", c.name, err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		joined := strings.Join(plan, " ")
		if !strings.Contains(joined, c.wantIndex) {
			t.Errorf("%s: plan %q does not use %s", c.name, joined, c.wantIndex)
		}
	}
}
