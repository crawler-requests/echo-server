package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Online password recovery.
//
// A password hash is one-way, so "forgot password" can only mean issuing a
// one-time token that lets the account holder set a new password. There is no
// email delivery in this self-hosted product (and adding SMTP would make the
// deployment story worse), so the token is handed over out-of-band: an admin
// generates it in the console, reads it to the user over whatever private
// channel they already share, and the user redeems it at /ui/.
//
// Security properties:
//   - 32 bytes of entropy, URL-safe, returned exactly once (plaintext never
//     stored — only its SHA-256, same contract as API keys),
//   - single use, and expires after 30 minutes,
//   - issuing a token requires admin; redeeming it requires nobody (the token
//     itself is the credential),
//   - every issue/redeem is audited,
//   - redemption is rate-limited per TCP peer so a stolen token cannot be
//     brute-forced and an attacker cannot spray guesses.

const (
	resetTokenTTL    = 30 * time.Minute
	resetTokenBytes  = 32
	resetIssueMaxAge = 24 * time.Hour // prune older rows
)

// hashResetToken derives the stored form of a token.
func hashResetToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// issuePasswordReset creates a token for username and returns the plaintext.
// It is the only place the plaintext exists.
func issuePasswordReset(username, issuedBy string) (string, time.Time, error) {
	initExtraDB()
	u, err := GetUser(username)
	if err != nil {
		return "", time.Time{}, err
	}
	raw := make([]byte, resetTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := "epr_" + base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now().UTC()
	expires := now.Add(resetTokenTTL)

	// Supersede any outstanding tokens for this account: a user following an
	// older link should not be able to reset after an admin reissued.
	_, _ = db.Exec(`DELETE FROM password_resets WHERE username = ? AND used_at = ''`, u.Username)
	_, err = db.Exec(`INSERT INTO password_resets(username, token_hash, created_at, expires_at, issued_by)
		VALUES(?,?,?,?,?)`,
		u.Username, hashResetToken(token), now.Format(time.RFC3339), expires.Format(time.RFC3339), issuedBy)
	if err != nil {
		return "", time.Time{}, err
	}
	// Opportunistic prune of stale rows.
	_, _ = db.Exec(`DELETE FROM password_resets WHERE created_at < ?`,
		now.Add(-resetIssueMaxAge).Format(time.RFC3339))
	return token, expires, nil
}

// redeemPasswordReset consumes a token and sets the new password atomically
// enough for a single-process server: the token is marked used before the
// password is written, so a replay cannot win a race.
func redeemPasswordReset(token, newPassword string) (string, error) {
	initExtraDB()
	if err := validatePassword(newPassword); err != nil {
		return "", err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("token is required")
	}
	h := hashResetToken(token)

	var id int64
	var username, expiresAt, usedAt string
	err := db.QueryRow(`SELECT id, username, expires_at, used_at FROM password_resets WHERE token_hash = ?`, h).
		Scan(&id, &username, &expiresAt, &usedAt)
	if err != nil {
		return "", errors.New("invalid or already-used reset token")
	}
	// Constant-time compare on the hash as defence in depth.
	if subtle.ConstantTimeCompare([]byte(h), []byte(hashResetToken(token))) != 1 {
		return "", errors.New("invalid reset token")
	}
	if usedAt != "" {
		return "", errors.New("this reset token has already been used")
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil || time.Now().UTC().After(exp) {
		return "", errors.New("this reset token has expired")
	}
	if _, err := GetUser(username); err != nil {
		return "", errors.New("the account no longer exists")
	}

	res, err := db.Exec(`UPDATE password_resets SET used_at = ? WHERE id = ? AND used_at = ''`,
		time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", errors.New("this reset token has already been used")
	}
	// Burn every other outstanding token for the account too.
	_, _ = db.Exec(`UPDATE password_resets SET used_at = ? WHERE username = ? AND used_at = ''`,
		time.Now().UTC().Format(time.RFC3339), username)

	if err := SetPassword(username, newPassword); err != nil {
		return "", err
	}
	return username, nil
}

// --------------------------------------------------------------------------
// HTTP surface

// passwordResetHandler is the admin-facing issuer: POST {username} -> token.
func passwordResetHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		u := currentUser(r)
		actor := "admin"
		if u != nil {
			actor = u.Username
		}
		token, expires, err := issuePasswordReset(strings.TrimSpace(req.Username), actor)
		if err != nil {
			writeUserError(w, err)
			return
		}
		RecordAudit(r, "password.reset.issue", req.Username, "expires="+expires.Format(time.RFC3339))
		// The plaintext token is returned exactly once; the stored form is a
		// hash, so refreshing this response is impossible by design.
		writeJSON(w, map[string]any{
			"username":   req.Username,
			"token":      token,
			"expires_at": expires.Format(time.RFC3339),
			"expires_in": int(resetTokenTTL.Seconds()),
			"note":       "Give this to the user privately. It works once and only for this account.",
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// passwordResetRedeemHandler is the public-facing consumer: POST {token,
// password} -> session for that account. No auth required: the token IS the
// credential, which is why it is short-lived and single-use.
func passwordResetRedeemHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	username, err := redeemPasswordReset(req.Token, req.Password)
	if err != nil {
		// Deliberately vague for bad tokens (no oracle for validity vs expiry),
		// but explicit for a weak password (the user can fix that).
		if errors.Is(err, errInvalidPassword) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := GetUser(username)
	if err != nil {
		http.Error(w, "account unavailable", http.StatusInternalServerError)
		return
	}
	RecordAuditDirect("password.reset.redeem", username, "self-service")
	tok, err := generateTokenFor(u)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"token": tok, "user": u})
}

// resetThrottleMiddleware rate-limits redemption by TCP peer: a stolen/leaked
// token must not be brute-forceable, and an attacker must not be able to spray
// guesses across many tokens. 20 attempts per 15 minutes is generous for a
// human and useless for a scanner.
func resetThrottleMiddleware(next http.HandlerFunc) http.HandlerFunc {
	const (
		limit  = 20
		window = 15 * time.Minute
	)
	return func(w http.ResponseWriter, r *http.Request) {
		peer := tcpPeer(r)
		if ok, retry := resetThrottleAllow(peer, limit, window); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			http.Error(w, "too many reset attempts; try again later", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

var resetThrottle = struct {
	sync.Mutex
	peers map[string]*resetPeer
}{peers: map[string]*resetPeer{}}

type resetPeer struct {
	n      int
	window time.Time
}

func resetThrottleAllow(peer string, limit int, window time.Duration) (bool, time.Duration) {
	now := time.Now()
	resetThrottle.Lock()
	defer resetThrottle.Unlock()
	if len(resetThrottle.peers) > 20000 {
		for k, v := range resetThrottle.peers {
			if now.After(v.window) {
				delete(resetThrottle.peers, k)
			}
		}
	}
	st := resetThrottle.peers[peer]
	if st == nil || now.After(st.window) {
		resetThrottle.peers[peer] = &resetPeer{n: 1, window: now.Add(window)}
		return true, 0
	}
	if st.n >= limit {
		return false, time.Until(st.window)
	}
	st.n++
	return true, 0
}
