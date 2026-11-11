package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// User is one console account. Password hashes never leave this file.
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"` // admin | viewer
	Disabled  bool   `json:"disabled"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	LastLogin string `json:"last_login,omitempty"`
}

const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"

	pbkdf2Iterations = 210000
	// 5 keeps existing admin/admin installations working after an upgrade.
	minPasswordLen = 5
	maxPasswordLen = 128
)

var (
	errUserNotFound       = errors.New("user not found")
	errUserExists         = errors.New("user already exists")
	errInvalidCredentials = errors.New("invalid username or password")
	errUserDisabled       = errors.New("user is disabled")
	errLastAdmin          = errors.New("the last enabled admin cannot be removed, disabled or demoted")
	errInvalidUsername    = errors.New("username must be 3-32 characters of a-z, 0-9, '.', '_' or '-'")
	errInvalidPassword    = fmt.Errorf("password must be %d-%d characters", minPasswordLen, maxPasswordLen)
	errInvalidRole        = errors.New("role must be admin or viewer")
	errSetupDone          = errors.New("initial setup has already been completed")
	errRegistrationOff    = errors.New("self-registration is disabled")
)

// initUsers bootstraps the first admin from the environment when requested.
// A fresh installation normally starts empty: the console then shows a setup
// page where the operator chooses their own admin username/password, so no
// well-known default password ever exists. For headless deployments,
// ECHO_SERVER_ADMIN_USERNAME (default "admin") + ECHO_SERVER_ADMIN_PASSWORD
// create that first admin at startup instead.
var usersOnce sync.Once

// setupMu serializes "is the table empty?" + "insert the first admin" so two
// concurrent setup requests cannot both create an initial account.
var setupMu sync.Mutex

func initUsers() {
	initDB()
	usersOnce.Do(func() {
		password := os.Getenv("ECHO_SERVER_ADMIN_PASSWORD")
		if password == "" {
			return
		}
		username := os.Getenv("ECHO_SERVER_ADMIN_USERNAME")
		if username == "" {
			username = "admin"
		}
		if _, err := CreateFirstAdmin(username, password); err != nil {
			if !errors.Is(err, errSetupDone) {
				log.Printf("user bootstrap from environment failed: %v", err)
			}
			return
		}
		log.Printf("created initial admin %q from ECHO_SERVER_ADMIN_PASSWORD", normalizeUsername(username))
	})
}

// NeedsSetup reports whether the installation has no accounts yet.
func NeedsSetup() (bool, error) {
	initDB()
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n == 0, err
}

// CreateFirstAdmin creates the very first account with the admin role. It is
// the only path allowed to run while the users table is empty, and it refuses
// to run once any account exists — this is what makes the first user an admin
// without shipping a default password.
func CreateFirstAdmin(username, password string) (*User, error) {
	initDB()
	setupMu.Lock()
	defer setupMu.Unlock()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		return nil, errSetupDone
	}
	return CreateUser(username, password, RoleAdmin)
}

// RegistrationEnabled reports the admin-controlled self-registration switch.
func RegistrationEnabled() bool {
	return GetConfig("allow_registration") == "true"
}

// RegisterUser creates a self-registered viewer account. Self-registered users
// are never admins; an admin can promote them later.
func RegisterUser(username, password string) (*User, error) {
	if !RegistrationEnabled() {
		return nil, errRegistrationOff
	}
	if needs, err := NeedsSetup(); err != nil {
		return nil, err
	} else if needs {
		// The first account must be created through setup (and is an admin).
		return nil, errSetupDone
	}
	return CreateUser(username, password, RoleViewer)
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func validUsername(username string) bool {
	if len(username) < 3 || len(username) > 32 {
		return false
	}
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validatePassword(password string) error {
	if len(password) < minPasswordLen || len(password) > maxPasswordLen {
		return errInvalidPassword
	}
	return nil
}

func validRole(role string) bool {
	return role == RoleAdmin || role == RoleViewer
}

// hashPassword returns a self-describing PBKDF2-SHA256 string:
// pbkdf2-sha256$<iterations>$<salt>$<key>.
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// verifyPassword checks a password against a stored hash in constant time.
func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 || iter > 10_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func userFromRow(row interface{ Scan(...any) error }) (*User, string, error) {
	var u User
	var disabled int
	var hash string
	err := row.Scan(&u.ID, &u.Username, &hash, &u.Role, &disabled, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin)
	if err != nil {
		return nil, "", err
	}
	u.Disabled = disabled != 0
	return &u, hash, nil
}

// GetUser looks up one account by (case-insensitive) username.
func GetUser(username string) (*User, error) {
	initDB()
	u, _, err := userFromRow(db.QueryRow(
		`SELECT id, username, password_hash, role, disabled, created_at, updated_at, last_login
		   FROM users WHERE username = ?`, normalizeUsername(username)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errUserNotFound
	}
	return u, err
}

// ListUsers returns all accounts ordered by creation.
func ListUsers() ([]*User, error) {
	initDB()
	rows, err := db.Query(
		`SELECT id, username, password_hash, role, disabled, created_at, updated_at, last_login
		   FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, _, err := userFromRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CreateUser inserts a new account. The first account must be an admin, which
// the bootstrap path guarantees.
func CreateUser(username, password, role string) (*User, error) {
	initDB()
	username = normalizeUsername(username)
	if !validUsername(username) {
		return nil, errInvalidUsername
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	if role == "" {
		role = RoleViewer
	}
	if !validRole(role) {
		return nil, errInvalidRole
	}
	if _, err := GetUser(username); err == nil {
		return nil, errUserExists
	} else if !errors.Is(err, errUserNotFound) {
		return nil, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := db.Exec(
		`INSERT INTO users(username, password_hash, role, disabled, created_at, updated_at)
		 VALUES(?,?,?,0,?,?)`, username, hash, role, now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: id, Username: username, Role: role, CreatedAt: now, UpdatedAt: now}, nil
}

// UpdateUser changes role, disabled state and (when password != "") the
// password. Empty role / nil disabled keep the current value.
func UpdateUser(username, password, role string, disabled *bool) (*User, error) {
	initDB()
	u, err := GetUser(username)
	if err != nil {
		return nil, err
	}
	newRole := u.Role
	if role != "" {
		if !validRole(role) {
			return nil, errInvalidRole
		}
		newRole = role
	}
	newDisabled := u.Disabled
	if disabled != nil {
		newDisabled = *disabled
	}
	if u.Role == RoleAdmin && (!u.Disabled) && (newRole != RoleAdmin || newDisabled) {
		if err := ensureNotLastAdmin(u.Username); err != nil {
			return nil, err
		}
	}
	hash := ""
	if password != "" {
		if err := validatePassword(password); err != nil {
			return nil, err
		}
		if hash, err = hashPassword(password); err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	q := `UPDATE users SET role = ?, disabled = ?, updated_at = ?`
	args := []any{newRole, boolToInt(newDisabled), now}
	if hash != "" {
		q += `, password_hash = ?`
		args = append(args, hash)
	}
	q += ` WHERE id = ?`
	args = append(args, u.ID)
	if _, err := db.Exec(q, args...); err != nil {
		return nil, err
	}
	return GetUser(u.Username)
}

// DeleteUser removes an account, refusing to delete the last enabled admin.
func DeleteUser(username string) error {
	initDB()
	u, err := GetUser(username)
	if err != nil {
		return err
	}
	if u.Role == RoleAdmin && !u.Disabled {
		if err := ensureNotLastAdmin(u.Username); err != nil {
			return err
		}
	}
	_, err = db.Exec(`DELETE FROM users WHERE id = ?`, u.ID)
	return err
}

// ensureNotLastAdmin errors when removing/demoting this admin would leave the
// system without an enabled admin account.
func ensureNotLastAdmin(username string) error {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND username <> ?`,
		normalizeUsername(username)).Scan(&n)
	if err != nil {
		return err
	}
	if n == 0 {
		return errLastAdmin
	}
	return nil
}

// SetPassword replaces the password hash without checking the old one (used by
// admins resetting an account).
func SetPassword(username, password string) error {
	initDB()
	if err := validatePassword(password); err != nil {
		return err
	}
	u, err := GetUser(username)
	if err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	_, err = db.Exec(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		hash, time.Now().UTC().Format(time.RFC3339), u.ID)
	return err
}

// AuthenticateUser verifies credentials and records the successful login.
func AuthenticateUser(username, password string) (*User, error) {
	initDB()
	u, err := GetUser(username)
	if err != nil {
		if errors.Is(err, errUserNotFound) {
			return nil, errInvalidCredentials
		}
		return nil, err
	}
	var hash string
	if err := db.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, u.ID).Scan(&hash); err != nil {
		return nil, err
	}
	if !verifyPassword(password, hash) {
		return nil, errInvalidCredentials
	}
	if u.Disabled {
		return nil, errUserDisabled
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = db.Exec(`UPDATE users SET last_login = ? WHERE id = ?`, now, u.ID)
	u.LastLogin = now
	return u, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
