package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtSecret = []byte("echo-server-secret-change-me") // in production load from env / SQLite
)

// Claims for admin JWT
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// generateToken creates a signed JWT for the given user (1h expiry)
func generateToken(username string) (string, error) {
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(jwtSecret)
}

// validateToken parses and validates the JWT
func validateToken(tokenStr string) (*Claims, bool) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, false
	}
	if claims, ok := token.Claims.(*Claims); ok {
		return claims, true
	}
	return nil, false
}

// authMiddleware protects admin routes with JWT (Authorization: Bearer <token>)
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if _, ok := validateToken(token); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
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

// loginHandler issues JWT after simple username/password check (demo: admin/admin)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username != "admin" || req.Password != "admin" {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	tok, _ := generateToken(req.Username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tok})
}

// randomToken generates a secure random API token
func randomToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
