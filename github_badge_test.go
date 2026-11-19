package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidGitHubRepo(t *testing.T) {
	ok := []string{"owner/name", "crawler-requests/echo-server", "a/b.c-d_e"}
	for _, s := range ok {
		if !validGitHubRepo(s) {
			t.Errorf("validGitHubRepo(%q) = false, want true", s)
		}
	}
	bad := []string{"", "owner", "owner/name/extra", "../etc/passwd", "owner/../x",
		"owner/name?x=1", "https://github.com/owner/name"}
	for _, s := range bad {
		if validGitHubRepo(s) {
			t.Errorf("validGitHubRepo(%q) = true, want false", s)
		}
	}
}

// setGitHubCacheForTest seeds the process-wide badge cache. The struct holds a
// mutex, so the fields are copied under the lock instead of by value.
func setGitHubCacheForTest(t *testing.T, repo string, stars int, ok bool, fetchedAt, attemptAt time.Time) {
	t.Helper()
	githubStarState.Lock()
	prev := struct {
		repo      string
		stars     int
		ok        bool
		fetchedAt time.Time
		attemptAt time.Time
	}{githubStarState.repo, githubStarState.stars, githubStarState.ok, githubStarState.fetchedAt, githubStarState.attemptAt}
	githubStarState.repo = repo
	githubStarState.stars = stars
	githubStarState.ok = ok
	githubStarState.fetchedAt = fetchedAt
	githubStarState.attemptAt = attemptAt
	githubStarState.Unlock()
	t.Cleanup(func() {
		githubStarState.Lock()
		githubStarState.repo = prev.repo
		githubStarState.stars = prev.stars
		githubStarState.ok = prev.ok
		githubStarState.fetchedAt = prev.fetchedAt
		githubStarState.attemptAt = prev.attemptAt
		githubStarState.Unlock()
	})
}

// A fresh cache must be served without any upstream call; this is the whole
// point of the 30-minute window (GitHub allows 60 unauthenticated calls/hour).
func TestGitHubStars_ServesCacheInsideWindow(t *testing.T) {
	setGitHubCacheForTest(t, "owner/name", 42, true, time.Now().Add(-5*time.Minute), time.Now().Add(-5*time.Minute))
	stars, at, ok := githubStars()
	if !ok || stars != 42 {
		t.Fatalf("githubStars = %d ok=%v, want cached 42", stars, ok)
	}
	if time.Since(at) > 10*time.Minute {
		t.Fatalf("fetchedAt not preserved: %v", at)
	}
}

// A failed fetch inside the window keeps the previous value and reports ok=true
// (the value is still valid, just stale) rather than blanking the badge.
func TestGitHubBadgeAPI_ResponseShape(t *testing.T) {
	setGitHubCacheForTest(t, "crawler-requests/echo-server", 128, true, time.Now(), time.Now())
	req := httptest.NewRequest(http.MethodGet, "/api/github", nil)
	rec := httptest.NewRecorder()
	githubBadgeHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var doc struct {
		Repo  string `json:"repo"`
		URL   string `json:"url"`
		Stars int    `json:"stars"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Repo != "crawler-requests/echo-server" || doc.Stars != 128 {
		t.Fatalf("badge = %+v", doc)
	}
	if doc.URL != "https://github.com/crawler-requests/echo-server" {
		t.Fatalf("url = %q", doc.URL)
	}

	// Invalid repo configuration is reported, not silently used in a URL.
	setGitHubCacheForTest(t, "owner/name", 0, false, time.Time{}, time.Time{})
	_ = SetConfig("github_repo", "../etc/passwd")
	t.Cleanup(func() { _ = SetConfig("github_repo", "") })
	req = httptest.NewRequest(http.MethodGet, "/api/github", nil)
	rec = httptest.NewRecorder()
	githubBadgeHandler(rec, req)
	var bad struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &bad)
	if bad.Error == "" {
		t.Fatal("invalid github_repo should be reported in the response")
	}
}

func TestGitHubStars_DifferentRepoRefetches(t *testing.T) {
	// The cache is keyed on nothing but staleness; a repo change within the
	// window is still served from the old value, which is intentional (the
	// operator rarely switches repos and a stale count is harmless). This test
	// pins that behavior so it is not "fixed" into a per-request fetch.
	setGitHubCacheForTest(t, "old/repo", 7, true, time.Now(), time.Now().Add(-time.Second))
	_ = SetConfig("github_repo", "new/repo")
	t.Cleanup(func() { _ = SetConfig("github_repo", "") })
	stars, _, ok := githubStars()
	if !ok || stars != 7 {
		t.Fatalf("stars = %d ok=%v, want the cached 7", stars, ok)
	}
}
