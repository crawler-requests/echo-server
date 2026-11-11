package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// decodeJSONBody decodes a small JSON request body (1 MiB cap).
func decodeJSONBody(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

// usersHandler manages console accounts (admin only).
//
//	GET    /api/users                 list accounts (no password material)
//	POST   /api/users                 create (username+password) or update (role/disabled/password)
//	DELETE /api/users?username=alice  remove an account
//
// The last enabled admin cannot be deleted, disabled or demoted, and an admin
// cannot delete or disable their own account.
func usersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users, err := ListUsers()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if users == nil {
			users = []*User{}
		}
		writeJSON(w, users)

	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
			Disabled *bool  `json:"disabled"`
		}
		if err := decodeJSONBody(r, &req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Username == "" {
			http.Error(w, "username is required", http.StatusBadRequest)
			return
		}
		_, err := GetUser(req.Username)
		switch {
		case errors.Is(err, errUserNotFound):
			if req.Password == "" {
				http.Error(w, "password is required for a new user", http.StatusBadRequest)
				return
			}
			u, cerr := CreateUser(req.Username, req.Password, req.Role)
			if cerr != nil {
				writeUserError(w, cerr)
				return
			}
			RecordAudit(r, "user.create", u.Username, "role="+u.Role)
			emitEvent("user.create", map[string]any{"actor": userName(r), "username": u.Username, "role": u.Role})
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, u)
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		default:
			if me := currentUser(r); me != nil && me.Username == normalizeUsername(req.Username) &&
				req.Disabled != nil && *req.Disabled {
				http.Error(w, "you cannot disable your own account", http.StatusBadRequest)
				return
			}
			u, uerr := UpdateUser(req.Username, req.Password, req.Role, req.Disabled)
			if uerr != nil {
				writeUserError(w, uerr)
				return
			}
			RecordAudit(r, "user.update", u.Username, "role="+u.Role)
			emitEvent("user.update", map[string]any{"actor": userName(r), "username": u.Username, "role": u.Role})
			writeJSON(w, u)
		}

	case http.MethodDelete:
		username := r.URL.Query().Get("username")
		if username == "" {
			http.Error(w, "username is required", http.StatusBadRequest)
			return
		}
		if me := currentUser(r); me != nil && me.Username == normalizeUsername(username) {
			http.Error(w, "you cannot delete your own account", http.StatusBadRequest)
			return
		}
		if err := DeleteUser(username); err != nil {
			if errors.Is(err, errUserNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			writeUserError(w, err)
			return
		}
		RecordAudit(r, "user.delete", normalizeUsername(username), "")
		emitEvent("user.delete", map[string]any{"actor": userName(r), "username": normalizeUsername(username)})
		w.WriteHeader(http.StatusNoContent)

	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// meHandler returns the authenticated account and its effective role.
func meHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, currentUser(r))
}

// changePasswordHandler lets any authenticated user rotate their own password
// by proving the current one.
func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	u := currentUser(r)
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := AuthenticateUser(u.Username, req.OldPassword); err != nil {
		http.Error(w, "current password is incorrect", http.StatusBadRequest)
		return
	}
	if err := SetPassword(u.Username, req.NewPassword); err != nil {
		writeUserError(w, err)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// setupStatusHandler is public: it tells the login page whether this is a
// fresh installation (show the first-admin wizard) and whether self-service
// registration is currently open.
//
//	GET /api/setup/status
func setupStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	needs, err := NeedsSetup()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	allow := RegistrationEnabled()
	writeJSON(w, map[string]bool{
		"needs_setup":        needs,
		"allow_registration": allow,
		"registration_open":  allow && !needs,
	})
}

// setupHandler creates the first account. It is public but only works while
// the users table is empty, and the account is always an admin. On success it
// returns a token so the browser lands directly in the console.
//
//	POST /api/setup {"username":"...","password":"..."}
func setupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	u, err := CreateFirstAdmin(req.Username, req.Password)
	if errors.Is(err, errSetupDone) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		writeUserError(w, err)
		return
	}
	tok, err := generateTokenFor(u)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"token": tok, "user": u})
}

// registerHandler is public self-service signup. It only works when an admin
// has set allow_registration=true, always creates a viewer, and never creates
// the first account (setup owns that).
//
//	POST /api/register {"username":"...","password":"..."}
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	u, err := RegisterUser(req.Username, req.Password)
	switch {
	case errors.Is(err, errRegistrationOff):
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	case errors.Is(err, errSetupDone):
		http.Error(w, "initial setup is required before self-registration", http.StatusConflict)
		return
	case errors.Is(err, errUserExists):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		writeUserError(w, err)
		return
	}
	tok, err := generateTokenFor(u)
	if err != nil {
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, map[string]any{"token": tok, "user": u})
}

// writeUserError maps domain errors to client errors; anything else is a 500.
func writeUserError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUserExists), errors.Is(err, errInvalidUsername),
		errors.Is(err, errInvalidPassword), errors.Is(err, errInvalidRole),
		errors.Is(err, errLastAdmin):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, errUserNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
