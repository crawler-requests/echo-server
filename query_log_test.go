package main

import (
	"testing"
)

// Client identification is persisted with each request so history — not just
// the live response — can answer "which clients hit us".
func TestQueryLogPersistsClientIdentification(t *testing.T) {
	initDB()
	rec := queryRecord{
		Method: "GET", Path: "/echo", IP: "198.51.100.9",
		ConnectionType: "datacenter", Country: "Testland",
		ClientName: "curl", ClientFamily: "cli", ClientSource: "ja4_measured",
		JA4: "t13i3111h2_e8f1e7e78f70_b26ce05bbdd6", JA3: "hash",
		UserAgent: "curl/8.5.0", Spoofed: true,
	}
	LogQueryDetailed(rec)
	FlushQueryLog()

	rows := fetchLogs(logFilter{IP: rec.IP, Limit: 5})
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	got := rows[0]
	for k, want := range map[string]string{
		"client_name": "curl", "client_family": "cli", "client_source": "ja4_measured",
		"ja4": rec.JA4, "spoofed": "true", "user_agent": "curl/8.5.0",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}

	// The new filters must narrow on those columns.
	if rows := fetchLogs(logFilter{IP: rec.IP, Family: "cli", Limit: 5}); len(rows) != 1 {
		t.Errorf("family filter dropped the row")
	}
	if rows := fetchLogs(logFilter{IP: rec.IP, Family: "browser", Limit: 5}); len(rows) != 0 {
		t.Errorf("family filter matched the wrong row")
	}
	spoofed := true
	if rows := fetchLogs(logFilter{IP: rec.IP, Spoofed: &spoofed, Limit: 5}); len(rows) != 1 {
		t.Errorf("spoofed filter dropped the row")
	}
	notSpoofed := false
	if rows := fetchLogs(logFilter{IP: rec.IP, Spoofed: &notSpoofed, Limit: 5}); len(rows) != 0 {
		t.Errorf("spoofed=false matched a spoofed row")
	}
	if rows := fetchLogs(logFilter{IP: rec.IP, Fingerprint: rec.JA4, Limit: 5}); len(rows) != 1 {
		t.Errorf("fingerprint filter dropped the row")
	}
}

// A long UA is truncated: the log is for triage, not archival.
func TestQueryLogTruncatesUserAgent(t *testing.T) {
	initDB()
	ua := ""
	for i := 0; i < 400; i++ {
		ua += "x"
	}
	LogQueryDetailed(queryRecord{Method: "GET", Path: "/echo", IP: "203.0.113.9", UserAgent: ua})
	FlushQueryLog()
	rows := fetchLogs(logFilter{IP: "203.0.113.9", Limit: 5})
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	if len(rows[0]["user_agent"]) > 200 {
		t.Fatalf("UA was not truncated: %d bytes", len(rows[0]["user_agent"]))
	}
}
