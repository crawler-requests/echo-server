package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// API keys are an alternative to the single shared api_token: each key has a
// name, a scope, an optional expiry and can be revoked without touching the
// others. Only the SHA-256 of the secret is stored; the plaintext is shown
// exactly once, when it is created.

func hashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func hmacHex(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func errWebhookStatus(status string) error { return errors.New("webhook returned " + status) }

func newAPIKeySecret() string { return "esk_" + randomToken() }

// apiKeyUser resolves an X-API-Key header to a synthetic account. The account
// name is prefixed so audit entries make clear that a key, not a person, acted.
func apiKeyUser(r *http.Request) (*User, bool) {
	key := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if key == "" {
		return nil, false
	}
	initExtraDB()
	var id int64
	var name, scope, expires string
	var enabled int
	hash := hashAPIKey(key)
	err := db.QueryRow(`SELECT id, name, scope, enabled, expires_at FROM api_keys WHERE key_hash = ?`, hash).
		Scan(&id, &name, &scope, &enabled, &expires)
	if err != nil || enabled == 0 {
		return nil, false
	}
	if expires != "" {
		if t, err := time.Parse(time.RFC3339, expires); err == nil && time.Now().After(t) {
			return nil, false
		}
	}
	// Constant-time compare as defence in depth against index timing leaks.
	if subtle.ConstantTimeCompare([]byte(hash), []byte(hashAPIKey(key))) != 1 {
		return nil, false
	}
	go func(id int64) {
		_, _ = db.Exec(`UPDATE api_keys SET last_used = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), id)
	}(id)
	role := RoleViewer
	if scope == RoleAdmin {
		role = RoleAdmin
	}
	return &User{ID: id, Username: "key:" + name, Role: role}, true
}

// apiKeysHandler lists, creates and revokes named API keys (admin only).
//
//	GET    /api/apikeys
//	POST   /api/apikeys  {"name","scope","expires_at"}
//	PATCH  /api/apikeys  {"id","enabled"}
//	DELETE /api/apikeys?id=
func apiKeysHandler(w http.ResponseWriter, r *http.Request) {
	initExtraDB()
	switch r.Method {
	case http.MethodGet:
		rows, err := db.Query(`SELECT id, name, prefix, scope, enabled, created_at, last_used, expires_at FROM api_keys ORDER BY id DESC`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id int64
			var name, prefix, scope, created, lastUsed, expires string
			var enabled int
			if rows.Scan(&id, &name, &prefix, &scope, &enabled, &created, &lastUsed, &expires) == nil {
				out = append(out, map[string]any{
					"id": id, "name": name, "prefix": prefix, "scope": scope,
					"enabled": enabled != 0, "created_at": created,
					"last_used": lastUsed, "expires_at": expires,
				})
			}
		}
		writeJSON(w, out)
	case http.MethodPost:
		var req struct {
			Name      string `json:"name"`
			Scope     string `json:"scope"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		if req.Scope != RoleAdmin {
			req.Scope = RoleViewer
		}
		if req.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, req.ExpiresAt); err != nil {
				http.Error(w, "expires_at must be RFC3339", http.StatusBadRequest)
				return
			}
		}
		secret := newAPIKeySecret()
		prefix := secret
		if len(prefix) > 12 {
			prefix = prefix[:12]
		}
		_, err := db.Exec(`INSERT INTO api_keys(name, key_hash, prefix, scope, enabled, created_at, expires_at) VALUES(?,?,?,?,1,?,?)`,
			req.Name, hashAPIKey(secret), prefix+"…", req.Scope, time.Now().UTC().Format(time.RFC3339), req.ExpiresAt)
		if err != nil {
			http.Error(w, "a key with this name already exists", http.StatusConflict)
			return
		}
		RecordAudit(r, "apikey.create", req.Name, "scope="+req.Scope)
		writeJSON(w, map[string]string{"status": "ok", "key": secret, "prefix": prefix, "name": req.Name})
	case http.MethodPatch:
		var req struct {
			ID      int64 `json:"id"`
			Enabled bool  `json:"enabled"`
		}
		if err := decodeJSONBody(r, &req); err != nil || req.ID == 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_, err := db.Exec(`UPDATE api_keys SET enabled = ? WHERE id = ?`, boolInt(req.Enabled), req.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	case http.MethodDelete:
		id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if id == 0 {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		var name string
		_ = db.QueryRow(`SELECT name FROM api_keys WHERE id = ?`, id).Scan(&name)
		if _, err := db.Exec(`DELETE FROM api_keys WHERE id = ?`, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		RecordAudit(r, "apikey.delete", name, "")
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// webhookHandler manages outbound event subscriptions.
func webhookHandler(w http.ResponseWriter, r *http.Request) {
	initExtraDB()
	switch r.Method {
	case http.MethodGet:
		rows, err := db.Query(`SELECT id, name, url, events, enabled, created_at, last_status, last_sent FROM webhooks ORDER BY id DESC`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id int64
			var name, url, events, created, lastStatus, lastSent string
			var enabled int
			if rows.Scan(&id, &name, &url, &events, &enabled, &created, &lastStatus, &lastSent) == nil {
				out = append(out, map[string]any{
					"id": id, "name": name, "url": url, "events": events,
					"enabled": enabled != 0, "created_at": created,
					"last_status": lastStatus, "last_sent": lastSent,
				})
			}
		}
		writeJSON(w, out)
	case http.MethodPost:
		var req struct {
			Name   string `json:"name"`
			URL    string `json:"url"`
			Secret string `json:"secret"`
			Events string `json:"events"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		req.URL = strings.TrimSpace(req.URL)
		if req.Name == "" || (!strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://")) {
			http.Error(w, "name and an http(s) URL are required", http.StatusBadRequest)
			return
		}
		if req.Secret == "" {
			req.Secret = randomToken()
		}
		if req.Events == "" {
			req.Events = "config.update,user.create,user.delete,security.alert"
		}
		_, err := db.Exec(`INSERT INTO webhooks(name, url, secret, events, enabled, created_at) VALUES(?,?,?,?,1,?)`,
			req.Name, req.URL, req.Secret, req.Events, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			http.Error(w, "a webhook with this name already exists", http.StatusConflict)
			return
		}
		RecordAudit(r, "webhook.create", req.Name, req.URL)
		writeJSON(w, map[string]string{"status": "ok"})
	case http.MethodPatch:
		var req struct {
			ID      int64 `json:"id"`
			Enabled bool  `json:"enabled"`
		}
		if err := decodeJSONBody(r, &req); err != nil || req.ID == 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_, err := db.Exec(`UPDATE webhooks SET enabled = ? WHERE id = ?`, boolInt(req.Enabled), req.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	case http.MethodDelete:
		id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if id == 0 {
			http.Error(w, "id is required", http.StatusBadRequest)
			return
		}
		if _, err := db.Exec(`DELETE FROM webhooks WHERE id = ?`, id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// webhookTestHandler sends a signed test payload to one webhook.
func webhookTestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID int64 `json:"id"`
	}
	if err := decodeJSONBody(r, &req); err != nil || req.ID == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	initExtraDB()
	var name, url, secret string
	if err := db.QueryRow(`SELECT name, url, secret FROM webhooks WHERE id = ?`, req.ID).Scan(&name, &url, &secret); err != nil {
		http.Error(w, "webhook not found", http.StatusNotFound)
		return
	}
	status, err := deliverWebhook(url, secret, "webhook.test", map[string]any{
		"event": "webhook.test", "webhook": name,
		"message": "这是一条来自 Echo Server 的测试事件",
		"ts":      time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		http.Error(w, "delivery failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	RecordAudit(r, "webhook.test", name, "status="+strconv.Itoa(status))
	writeJSON(w, map[string]any{"status": "ok", "http_status": status})
}

// emitEvent fans an event out to every enabled, subscribed webhook without
// blocking the request that caused it.
func emitEvent(event string, payload map[string]any) {
	initExtraDB()
	rows, err := db.Query(`SELECT id, name, url, secret, events FROM webhooks WHERE enabled = 1`)
	if err != nil {
		return
	}
	type target struct {
		id                     int64
		name, url, secret, evs string
	}
	var targets []target
	for rows.Next() {
		var t target
		if rows.Scan(&t.id, &t.name, &t.url, &t.secret, &t.evs) == nil {
			targets = append(targets, t)
		}
	}
	rows.Close()
	for _, t := range targets {
		if !eventSubscribed(t.evs, event) {
			continue
		}
		go func(t target) {
			payload["event"] = event
			payload["ts"] = time.Now().UTC().Format(time.RFC3339)
			status, err := deliverWebhook(t.url, t.secret, event, payload)
			result := strconv.Itoa(status)
			if err != nil {
				result = "error: " + err.Error()
			}
			_, _ = db.Exec(`UPDATE webhooks SET last_status = ?, last_sent = ? WHERE id = ?`,
				result, time.Now().UTC().Format(time.RFC3339), t.id)
			if err != nil {
				Notify("warning", "Webhook 投递失败", t.name+" → "+err.Error(), "webhook")
			}
		}(t)
	}
}

func eventSubscribed(list, event string) bool {
	if strings.TrimSpace(list) == "" || list == "*" {
		return true
	}
	for _, e := range strings.Split(list, ",") {
		if strings.TrimSpace(e) == event || strings.TrimSpace(e) == "*" {
			return true
		}
	}
	return false
}

// deliverWebhook posts a JSON payload and an HMAC signature header. The
// signature is hex(HMAC-SHA256(secret, body)); receivers can verify it.
func deliverWebhook(url, secret, event string, payload map[string]any) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Echo-Event", event)
	req.Header.Set("X-Echo-Signature", "sha256="+hmacHex(secret, body))
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return resp.StatusCode, errWebhookStatus(resp.Status)
	}
	return resp.StatusCode, nil
}
