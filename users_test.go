package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// resetUsers gives every test an empty users table with an explicit admin
// account, and leaves the table empty for the next test. It does not rely on
// environment bootstrap: production installs start empty by design.
func resetUsers(t *testing.T) {
	t.Helper()
	initDB()
	if _, err := db.Exec(`DELETE FROM users`); err != nil {
		t.Fatalf("clear users: %v", err)
	}
	usersOnce = sync.Once{}
	if _, err := CreateUser("admin", "admin", RoleAdmin); err != nil {
		t.Fatalf("create test admin: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM users`)
		usersOnce = sync.Once{}
	})
}

func TestPasswordHashing(t *testing.T) {
	h1, err := hashPassword("s3cret-password")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h1, "s3cret-password") {
		t.Fatal("hash contains the plaintext password")
	}
	if !strings.HasPrefix(h1, "pbkdf2-sha256$") {
		t.Fatalf("unexpected format: %s", h1)
	}
	if !verifyPassword("s3cret-password", h1) {
		t.Fatal("correct password rejected")
	}
	if verifyPassword("wrong", h1) {
		t.Fatal("wrong password accepted")
	}
	h2, _ := hashPassword("s3cret-password")
	if h1 == h2 {
		t.Fatal("salt is not random: equal hashes")
	}
	for _, bad := range []string{"", "plain", "pbkdf2-sha256$x$y$z", "md5$1$a$b"} {
		if verifyPassword("anything", bad) {
			t.Fatalf("malformed hash accepted: %q", bad)
		}
	}
}

func TestUserLifecycle(t *testing.T) {
	resetUsers(t)

	admin, err := GetUser("admin")
	if err != nil {
		t.Fatalf("bootstrap admin missing: %v", err)
	}
	if admin.Role != RoleAdmin || admin.Disabled {
		t.Fatalf("bootstrap admin = %+v", admin)
	}
	if _, err := AuthenticateUser("ADMIN", "admin"); err != nil {
		t.Fatalf("case-insensitive login failed: %v", err)
	}
	if _, err := AuthenticateUser("admin", "nope"); !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("wrong password error = %v", err)
	}

	u, err := CreateUser("Alice", "secret1", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" || u.Role != RoleViewer {
		t.Fatalf("created = %+v", u)
	}
	if _, err := CreateUser("alice", "another1", RoleViewer); !errors.Is(err, errUserExists) {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := CreateUser("x", "secret1", RoleViewer); !errors.Is(err, errInvalidUsername) {
		t.Fatalf("short username error = %v", err)
	}
	if _, err := CreateUser("bob", "123", RoleViewer); !errors.Is(err, errInvalidPassword) {
		t.Fatalf("short password error = %v", err)
	}
	if _, err := CreateUser("bob", "secret1", "root"); !errors.Is(err, errInvalidRole) {
		t.Fatalf("bad role error = %v", err)
	}

	if _, err := UpdateUser("alice", "", RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := AuthenticateUser("alice", "secret1"); err != nil {
		t.Fatal(err)
	}
	disabled := true
	if _, err := UpdateUser("alice", "", "", &disabled); err != nil {
		t.Fatal(err)
	}
	if _, err := AuthenticateUser("alice", "secret1"); !errors.Is(err, errUserDisabled) {
		t.Fatalf("disabled login error = %v", err)
	}
	disabled = false
	if _, err := UpdateUser("alice", "", "", &disabled); err != nil {
		t.Fatal(err)
	}
	if _, err := AuthenticateUser("alice", "secret1"); err != nil {
		t.Fatalf("re-enabled login failed: %v", err)
	}

	if err := SetPassword("alice", "changed1"); err != nil {
		t.Fatal(err)
	}
	if _, err := AuthenticateUser("alice", "changed1"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := GetUser("alice"); !errors.Is(err, errUserNotFound) {
		t.Fatalf("deleted user still present: %v", err)
	}
}

func TestLastAdminProtection(t *testing.T) {
	resetUsers(t)

	if err := DeleteUser("admin"); !errors.Is(err, errLastAdmin) {
		t.Fatalf("delete last admin = %v", err)
	}
	if _, err := UpdateUser("admin", "", RoleViewer, nil); !errors.Is(err, errLastAdmin) {
		t.Fatalf("demote last admin = %v", err)
	}
	disabled := true
	if _, err := UpdateUser("admin", "", "", &disabled); !errors.Is(err, errLastAdmin) {
		t.Fatalf("disable last admin = %v", err)
	}

	// With a second admin, the first may be demoted or deleted.
	if _, err := CreateUser("second", "secret1", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateUser("admin", "", RoleViewer, nil); err != nil {
		t.Fatalf("demote with backup admin: %v", err)
	}
	if _, err := UpdateUser("admin", "", RoleAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser("second"); err != nil {
		t.Fatal(err)
	}
}

func TestLoginAndUserAPI(t *testing.T) {
	resetUsers(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", loginHandler)
	mux.HandleFunc("/api/me", authMiddleware(meHandler))
	mux.HandleFunc("/api/me/password", authMiddleware(changePasswordHandler))
	mux.HandleFunc("/api/users", adminMiddleware(usersHandler))
	mux.HandleFunc("/api/write", adminWriteMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mux.HandleFunc("/api/config", adminWriteMiddleware(configHandler))
	prevToken := GetConfig("ipinfo_token")
	_ = SetConfig("ipinfo_token", "tok-secret")
	t.Cleanup(func() { _ = SetConfig("ipinfo_token", prevToken) })
	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(method, path, nil)
		} else {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}
	login := func(username, password string) (string, *httptest.ResponseRecorder) {
		t.Helper()
		rec := call(http.MethodPost, "/api/login", "", `{"username":"`+username+`","password":"`+password+`"}`)
		var body struct {
			Token string `json:"token"`
			User  User   `json:"user"`
		}
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
		}
		return body.Token, rec
	}

	adminToken, rec := login("admin", "admin")
	if rec.Code != http.StatusOK || adminToken == "" {
		t.Fatalf("admin login = %d %s", rec.Code, rec.Body.String())
	}
	if _, rec := login("admin", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login status = %d", rec.Code)
	}

	rec = call(http.MethodGet, "/api/users", adminToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list users = %d %s", rec.Code, rec.Body.String())
	}
	var list []User
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 {
		t.Fatalf("users = %+v err=%v", list, err)
	}

	rec = call(http.MethodPost, "/api/users", adminToken, `{"username":"bob","password":"secret1","role":"viewer"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create bob = %d %s", rec.Code, rec.Body.String())
	}
	// Posting an existing username updates it (role/disabled/password).
	rec = call(http.MethodPost, "/api/users", adminToken, `{"username":"bob","role":"viewer"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("upsert existing = %d %s", rec.Code, rec.Body.String())
	}

	bobToken, rec := login("bob", "secret1")
	if rec.Code != http.StatusOK {
		t.Fatalf("bob login = %d %s", rec.Code, rec.Body.String())
	}
	rec = call(http.MethodGet, "/api/me", bobToken, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"role":"viewer"`) {
		t.Fatalf("me = %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodGet, "/api/users", bobToken, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer list users = %d", rec.Code)
	}
	// Viewers can read configuration-like endpoints but not change anything.
	if rec := call(http.MethodGet, "/api/write", bobToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("viewer GET = %d", rec.Code)
	}
	if rec := call(http.MethodPost, "/api/write", bobToken, "{}"); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST = %d", rec.Code)
	}
	if rec := call(http.MethodPost, "/api/write", adminToken, "{}"); rec.Code != http.StatusOK {
		t.Fatalf("admin POST = %d", rec.Code)
	}
	// Config is readable by viewers, but secrets are masked.
	rec = call(http.MethodGet, "/api/config", bobToken, "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "tok-secret") ||
		!strings.Contains(rec.Body.String(), `"ipinfo_token":"***"`) {
		t.Fatalf("viewer config = %d %s", rec.Code, rec.Body.String())
	}
	rec = call(http.MethodGet, "/api/config", adminToken, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "tok-secret") {
		t.Fatalf("admin config = %d %s", rec.Code, rec.Body.String())
	}

	// Self-service password rotation requires the old password.
	rec = call(http.MethodPost, "/api/me/password", bobToken, `{"old_password":"wrong","new_password":"secret2"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong old password = %d", rec.Code)
	}
	rec = call(http.MethodPost, "/api/me/password", bobToken, `{"old_password":"secret1","new_password":"secret2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("change password = %d %s", rec.Code, rec.Body.String())
	}
	if _, rec := login("bob", "secret1"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old password still works: %d", rec.Code)
	}
	bobToken, rec = login("bob", "secret2")
	if rec.Code != http.StatusOK {
		t.Fatalf("new password login = %d", rec.Code)
	}

	// An admin can reset another account's password without the old one.
	rec = call(http.MethodPost, "/api/users", adminToken, `{"username":"bob","password":"reset123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin reset = %d %s", rec.Code, rec.Body.String())
	}
	if _, rec := login("bob", "reset123"); rec.Code != http.StatusOK {
		t.Fatalf("reset password login = %d", rec.Code)
	}

	// Disabling revokes an already issued token and blocks login.
	rec = call(http.MethodPost, "/api/users", adminToken, `{"username":"bob","disabled":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable bob = %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodGet, "/api/me", bobToken, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled token accepted: %d", rec.Code)
	}
	if _, rec := login("bob", "reset123"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled login = %d", rec.Code)
	}

	// Self-destruction is rejected; normal deletion works.
	if rec := call(http.MethodDelete, "/api/users?username=admin", adminToken, ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("self delete = %d", rec.Code)
	}
	if rec := call(http.MethodDelete, "/api/users?username=bob", adminToken, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete bob = %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodDelete, "/api/users?username=bob", adminToken, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing = %d", rec.Code)
	}
}

func TestBootstrapAdminFromEnv(t *testing.T) {
	initDB()
	_, _ = db.Exec(`DELETE FROM users`)
	usersOnce = sync.Once{}
	t.Setenv("ECHO_SERVER_ADMIN_USERNAME", "root")
	t.Setenv("ECHO_SERVER_ADMIN_PASSWORD", "envpass123")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM users`)
		usersOnce = sync.Once{}
	})
	initUsers()
	u, err := AuthenticateUser("root", "envpass123")
	if err != nil {
		t.Fatalf("env admin password rejected: %v", err)
	}
	if u.Role != RoleAdmin {
		t.Fatalf("env bootstrap role = %q", u.Role)
	}
	if _, err := AuthenticateUser("admin", "admin"); !errors.Is(err, errInvalidCredentials) {
		t.Fatalf("default account exists after env seed: %v", err)
	}
	// Running again with accounts present must not create or overwrite anyone.
	usersOnce = sync.Once{}
	initUsers()
	if _, err := AuthenticateUser("root", "envpass123"); err != nil {
		t.Fatalf("second bootstrap damaged the account: %v", err)
	}
}

func TestFirstRunSetup(t *testing.T) {
	initDB()
	_, _ = db.Exec(`DELETE FROM users`)
	usersOnce = sync.Once{}
	_ = SetConfig("allow_registration", "")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM users`)
		usersOnce = sync.Once{}
		_ = SetConfig("allow_registration", "")
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/setup/status", setupStatusHandler)
	mux.HandleFunc("/api/setup", setupHandler)
	mux.HandleFunc("/api/register", registerHandler)
	mux.HandleFunc("/api/me", authMiddleware(meHandler))
	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(method, path, nil)
		} else {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}

	if needs, err := NeedsSetup(); err != nil || !needs {
		t.Fatalf("fresh install needs setup = %v err=%v", needs, err)
	}
	rec := call(http.MethodGet, "/api/setup/status", "", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"needs_setup":true`) ||
		!strings.Contains(rec.Body.String(), `"registration_open":false`) {
		t.Fatalf("setup status = %d %s", rec.Code, rec.Body.String())
	}
	// Registration cannot create the first account, even if an admin enabled it.
	_ = SetConfig("allow_registration", "true")
	if rec := call(http.MethodPost, "/api/register", "", `{"username":"bob","password":"secret1"}`); rec.Code != http.StatusConflict {
		t.Fatalf("register before setup = %d %s", rec.Code, rec.Body.String())
	}
	_ = SetConfig("allow_registration", "")

	// Invalid first admin input is rejected with a 400 and setup stays open.
	if rec := call(http.MethodPost, "/api/setup", "", `{"username":"x","password":"secret1"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid setup username = %d %s", rec.Code, rec.Body.String())
	}
	if needs, _ := NeedsSetup(); !needs {
		t.Fatal("failed setup consumed the setup slot")
	}

	rec = call(http.MethodPost, "/api/setup", "", `{"username":"Owner","password":"ownersecret"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup = %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Token string `json:"token"`
		User  User   `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Token == "" || created.User.Username != "owner" || created.User.Role != RoleAdmin {
		t.Fatalf("setup response = %+v", created)
	}
	if rec := call(http.MethodGet, "/api/me", created.Token, ""); rec.Code != http.StatusOK {
		t.Fatalf("setup token unusable: %d %s", rec.Code, rec.Body.String())
	}
	if needs, _ := NeedsSetup(); needs {
		t.Fatal("setup still open after first admin was created")
	}
	rec = call(http.MethodGet, "/api/setup/status", "", "")
	if !strings.Contains(rec.Body.String(), `"needs_setup":false`) {
		t.Fatalf("status after setup = %s", rec.Body.String())
	}
	// Setup is one-shot.
	if rec := call(http.MethodPost, "/api/setup", "", `{"username":"other","password":"secret1"}`); rec.Code != http.StatusConflict {
		t.Fatalf("second setup = %d %s", rec.Code, rec.Body.String())
	}
}

func TestSelfRegistration(t *testing.T) {
	resetUsers(t)
	_ = SetConfig("allow_registration", "")
	t.Cleanup(func() { _ = SetConfig("allow_registration", "") })

	mux := http.NewServeMux()
	mux.HandleFunc("/api/setup/status", setupStatusHandler)
	mux.HandleFunc("/api/register", registerHandler)
	mux.HandleFunc("/api/me", authMiddleware(meHandler))
	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(method, path, nil)
		} else {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec
	}

	// Off by default: the endpoint refuses and the UI hides the entry.
	rec := call(http.MethodPost, "/api/register", "", `{"username":"bob","password":"secret1"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("register while disabled = %d %s", rec.Code, rec.Body.String())
	}
	rec = call(http.MethodGet, "/api/setup/status", "", "")
	if !strings.Contains(rec.Body.String(), `"registration_open":false`) {
		t.Fatalf("status while disabled = %s", rec.Body.String())
	}

	_ = SetConfig("allow_registration", "true")
	rec = call(http.MethodGet, "/api/setup/status", "", "")
	if !strings.Contains(rec.Body.String(), `"registration_open":true`) {
		t.Fatalf("status while enabled = %s", rec.Body.String())
	}
	// Self-registered accounts are viewers; role in the request is ignored.
	rec = call(http.MethodPost, "/api/register", "", `{"username":"Bob","password":"secret1","role":"admin"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Token string `json:"token"`
		User  User   `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.User.Username != "bob" || created.User.Role != RoleViewer || created.Token == "" {
		t.Fatalf("registered user = %+v", created.User)
	}
	rec = call(http.MethodGet, "/api/me", created.Token, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"role":"viewer"`) {
		t.Fatalf("registered me = %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "/api/register", "", `{"username":"bob","password":"other1"}`); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate register = %d %s", rec.Code, rec.Body.String())
	}
	if rec := call(http.MethodPost, "/api/register", "", `{"username":"carol","password":"123"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("short password register = %d %s", rec.Code, rec.Body.String())
	}

	// Turning the switch off closes signup immediately.
	_ = SetConfig("allow_registration", "")
	rec = call(http.MethodPost, "/api/register", "", `{"username":"carol","password":"secret1"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("register after disable = %d %s", rec.Code, rec.Body.String())
	}
}
