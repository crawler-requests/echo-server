package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GitHub repository badge.
//
// The console shows a "star us on GitHub" badge in the header. The star count
// is fetched from the public GitHub API and cached process-wide for 30 minutes:
// GitHub's unauthenticated limit is 60 requests/hour per IP, and a console that
// reloaded the count on every page view would burn it instantly (and be rude to
// the API besides). On any failure the last successful value is served, so the
// badge keeps rendering a stale-but-correct number instead of dropping out.

const (
	// githubCacheTTL is the minimum interval between upstream refreshes.
	githubCacheTTL = 30 * time.Minute
	// githubAPITimeout bounds one GitHub API call. The endpoint is not on the
	// echo path, but a hung request would pile up console handlers.
	githubAPITimeout = 5 * time.Second
	// defaultGitHubRepo is what the badge links to when the operator has not
	// set github_repo.
	defaultGitHubRepo = "crawler-requests/echo-server"
)

// githubStarState is the process-wide cache. A single mutex covers it: the
// critical section is a field read, and the slow upstream call happens outside
// the lock (see githubStars).
var githubStarState = struct {
	sync.Mutex
	repo      string
	stars     int
	ok        bool      // a successful upstream answer has been stored
	fetchedAt time.Time // when the last successful fetch happened
	attemptAt time.Time // when the last attempt (success or failure) happened
}{}

// githubRepo returns the configured owner/name, falling back to the built-in.
func githubRepo() string {
	if v := strings.TrimSpace(GetConfig("github_repo")); v != "" {
		return v
	}
	return defaultGitHubRepo
}

// validGitHubRepo rejects values that could escape into the API URL.
func validGitHubRepo(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return false
		}
		for _, r := range p {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
				r == '-' || r == '_' || r == '.') {
				return false
			}
		}
	}
	return true
}

// githubStars fetches stargazers_count for repo, honoring the 30-minute cache.
// It never returns an error to the caller: a failed fetch yields the previous
// value (when one exists) and ok=false so the UI can mark it stale.
func githubStars() (stars int, fetchedAt time.Time, ok bool) {
	repo := githubRepo()

	githubStarState.Lock()
	if !githubStarState.attemptAt.IsZero() && time.Since(githubStarState.attemptAt) < githubCacheTTL {
		// Inside the window (whether the last attempt worked or not): serve
		// whatever is stored. Repeating the request does not re-hit GitHub.
		s, at, good := githubStarState.stars, githubStarState.fetchedAt, githubStarState.ok
		githubStarState.Unlock()
		return s, at, good
	}
	// Mark the attempt before releasing the lock: concurrent console requests
	// then see "a fetch is in flight / recently attempted" and read the cached
	// value instead of firing a second upstream call.
	githubStarState.attemptAt = time.Now()
	githubStarState.Unlock()

	s, at, good := fetchGitHubStars(repo)
	githubStarState.Lock()
	defer githubStarState.Unlock()
	if good {
		githubStarState.repo = repo
		githubStarState.stars = s
		githubStarState.fetchedAt = at
		githubStarState.ok = true
		return s, at, true
	}
	return githubStarState.stars, githubStarState.fetchedAt, githubStarState.ok
}

// fetchGitHubStars performs one upstream call.
func fetchGitHubStars(repo string) (int, time.Time, bool) {
	if !validGitHubRepo(repo) {
		return 0, time.Time{}, false
	}
	client := &http.Client{Timeout: githubAPITimeout}
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/"+repo, nil)
	if err != nil {
		return 0, time.Time{}, false
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "echo-server-github-badge")
	resp, err := client.Do(req)
	if err != nil {
		return 0, time.Time{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, time.Time{}, false
	}
	var doc struct {
		Stars    int    `json:"stargazers_count"`
		FullName string `json:"full_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return 0, time.Time{}, false
	}
	if doc.Stars < 0 {
		return 0, time.Time{}, false
	}
	return doc.Stars, time.Now().UTC(), true
}

// githubBadgeHandler serves the badge state to the console. It is not on the
// echo path and never exposes anything the console could not already read.
func githubBadgeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	repo := githubRepo()
	stars, at, ok := githubStars()
	out := map[string]any{
		"repo":   repo,
		"url":    "https://github.com/" + repo,
		"stars":  stars,
		"cached": ok,
	}
	if ok {
		out["fetched_at"] = at.Format(time.RFC3339)
	}
	if !validGitHubRepo(repo) {
		out["error"] = fmt.Sprintf("github_repo %q is not a valid owner/name", repo)
	}
	writeJSON(w, out)
}
