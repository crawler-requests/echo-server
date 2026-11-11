package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The signing key is loaded once per process: ECHO_SERVER_JWT_SECRET wins,
// otherwise a random key is generated and persisted in SQLite so sessions
// survive a restart. It is independent from every user password.
var (
	jwtSecretOnce    sync.Once
	jwtSecretMu      sync.RWMutex
	jwtSecretKey     []byte
	jwtSecretFromEnv bool
)

func getJWTSecret() []byte {
	jwtSecretOnce.Do(func() {
		secret := os.Getenv("ECHO_SERVER_JWT_SECRET")
		if secret != "" {
			jwtSecretFromEnv = true
		} else {
			secret = GetConfig("jwt_secret")
		}
		if secret == "" {
			secret = randomToken()
			_ = SetConfig("jwt_secret", secret)
		}
		jwtSecretMu.Lock()
		jwtSecretKey = []byte(secret)
		jwtSecretMu.Unlock()
	})
	jwtSecretMu.RLock()
	defer jwtSecretMu.RUnlock()
	return jwtSecretKey
}

// rotateJWTSecret invalidates every issued JWT immediately. It is refused
// when the secret comes from ECHO_SERVER_JWT_SECRET, because the operator owns
// that value and restarting would otherwise silently undo the rotation.
func rotateJWTSecret() error {
	getJWTSecret()
	if jwtSecretFromEnv {
		return errors.New("签名密钥来自 ECHO_SERVER_JWT_SECRET，请在该环境变量中轮换后重启")
	}
	secret := randomToken()
	if err := SetConfig("jwt_secret", secret); err != nil {
		return err
	}
	jwtSecretMu.Lock()
	jwtSecretKey = []byte(secret)
	jwtSecretMu.Unlock()
	return nil
}

// Claims for admin JWT
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role,omitempty"`
	jwt.RegisteredClaims
}

// generateTokenFor creates a signed JWT for the given user (12h expiry).
func generateTokenFor(u *User) (string, error) {
	claims := &Claims{
		Username: u.Username,
		Role:     u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.Username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(12 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(getJWTSecret())
}

// validateToken parses and validates the JWT (HS256 only).
func validateToken(tokenStr string) (*Claims, bool) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return getJWTSecret(), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !token.Valid {
		return nil, false
	}
	if claims, ok := token.Claims.(*Claims); ok {
		return claims, true
	}
	return nil, false
}

type userCtxKey struct{}

// authenticatedUser resolves the bearer token AND re-reads the account, so a
// disabled or deleted user loses access immediately — no waiting for the JWT
// to expire.
func authenticatedUser(r *http.Request) (*User, bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return apiKeyUser(r)
	}
	claims, ok := validateToken(strings.TrimPrefix(auth, "Bearer "))
	if !ok {
		return apiKeyUser(r)
	}
	u, err := GetUser(claims.Username)
	if err != nil || u.Disabled {
		return nil, false
	}
	return u, true
}

// authMiddleware protects admin routes with JWT (Authorization: Bearer <jwt>),
// requiring an existing, enabled account.
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := authenticatedUser(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userCtxKey{}, u)))
	}
}

// adminMiddleware additionally requires the admin role. The role is read from
// SQLite, not from the token, so demoting a user takes effect immediately.
func adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if u := currentUser(r); u == nil || u.Role != RoleAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// adminWriteMiddleware allows every enabled user to read (GET/HEAD) but only
// admins to change anything. This is what makes the "viewer" role read-only.
func adminWriteMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next(w, r)
			return
		}
		if u := currentUser(r); u == nil || u.Role != RoleAdmin {
			http.Error(w, "forbidden: view-only account", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// currentUser returns the account attached by authMiddleware.
func currentUser(r *http.Request) *User {
	u, _ := r.Context().Value(userCtxKey{}).(*User)
	return u
}

// apiTokenMiddleware allows access via X-API-Token header for non-browser clients
func apiTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-API-Token")
		if tok == "" {
			tok = r.URL.Query().Get("token")
		}
		// simple token check stored in SQLite under key "api_token"
		expected := GetConfig("api_token")
		if expected != "" && tok != expected {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// isAuthorized reports whether the request carries a valid JWT for an enabled
// user or the configured API token. Used when require_token is enabled.
func isAuthorized(r *http.Request) bool {
	if _, ok := authenticatedUser(r); ok {
		return true
	}
	expected := GetConfig("api_token")
	if expected == "" {
		return false
	}
	tok := r.Header.Get("X-API-Token")
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	return tok == expected
}

// loginHandler validates credentials against the users table and issues a JWT.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	initUsers()
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	u, err := AuthenticateUser(req.Username, req.Password)
	if err != nil {
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	tok, err := generateTokenFor(u)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"token": tok, "user": u})
}

// randomToken generates a secure random API token
func randomToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
