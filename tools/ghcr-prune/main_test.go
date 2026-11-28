package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func at(sec int) time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(sec) * time.Second)
}

// publish builds the five versions one multi-arch Buildx push creates, as
// observed on GHCR: an index manifest carrying the tags, two platform child
// manifests, two attestation manifests.
func publish(id int64, created time.Time, tags ...string) []version {
	return []version{
		{ID: id, Name: "sha256:index", CreatedAt: created, Tags: tags},
		{ID: id + 1, Name: "sha256:amd64", CreatedAt: created.Add(time.Second)},
		{ID: id + 2, Name: "sha256:arm64", CreatedAt: created.Add(2 * time.Second)},
		{ID: id + 3, Name: "sha256:attest-amd64", CreatedAt: created.Add(3 * time.Second)},
		{ID: id + 4, Name: "sha256:attest-arm64", CreatedAt: created.Add(4 * time.Second)},
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func ids(vs []version) []int64 {
	out := make([]int64, len(vs))
	for i, v := range vs {
		out[i] = v.ID
	}
	return out
}

func releaseIDs(rs []release) []int64 {
	out := make([]int64, len(rs))
	for i, r := range rs {
		out[i] = r.Index.ID
	}
	return out
}

func TestDecideKeepsNewestReleasesWithTheirFragments(t *testing.T) {
	// v1.0.1 (no floating tags), v1.0.2, v1.0.3 with `1.0.3 1.0 1 latest`,
	// and v1.0.4 with `1.0.4 1.0 1 latest`. Keeping 2 removes the five
	// versions of v1.0.1 and of v1.0.2; the aliases survive on 1.0.3/1.0.4.
	var all []version
	all = append(all, publish(100, at(0), "1.0.1")...)
	all = append(all, publish(200, at(600), "1.0.2")...)
	all = append(all, publish(300, at(1200), "1.0.3", "1.0", "1", "latest")...)
	all = append(all, publish(400, at(1800), "1.0.4", "1.0", "1", "latest")...)

	p := decide(all, 2)

	if got := len(p.Keep); got != 2 {
		t.Fatalf("kept %d releases, want 2: %v", got, releaseIDs(p.Keep))
	}
	got := ids(p.versionsToDelete())
	want := []int64{100, 101, 102, 103, 104, 200, 201, 202, 203, 204}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("deleted %v, want %v", got, want)
	}
	// No fragment of a kept release may be swept up.
	for _, r := range p.Keep {
		for _, f := range r.Fragments {
			if f.ID/100 == 1 {
				t.Fatalf("kept release %d got fragment %d of a dropped release", r.Index.ID, f.ID)
			}
		}
	}
}

func TestDecideRescuesTheOnlyVersionCarryingAnAlias(t *testing.T) {
	// 1.0.3 carries `1` and `latest`; 1.1.0 then ships `1.1`, `1`, `latest`.
	// Keeping 2 must not delete 1.1.0's predecessor 1.0.3 — it is the only
	// version left tagged `1.0`.
	var all []version
	all = append(all, publish(100, at(0), "1.0.0")...)
	all = append(all, publish(200, at(600), "1.0.1")...)
	all = append(all, publish(300, at(1200), "1.1.0", "1.1", "1", "latest")...)

	p := decide(all, 2)

	if len(p.Rescued) != 0 {
		// 1.0.1 carries no alias, so nothing to rescue: it goes.
		t.Fatalf("unexpected rescue: %v", ids(p.Rescued))
	}
	if got := ids(p.versionsToDelete()); fmt.Sprint(got) != fmt.Sprint([]int64{100, 101, 102, 103, 104}) {
		t.Fatalf("deleted %v, want v1.0.0's five versions", got)
	}

	// Now the case that does rescue: every release carries `latest` but no
	// release carries `1.0`, and the oldest of the window is the only `1.0`.
	var all2 []version
	all2 = append(all2, publish(500, at(0), "1.0.0", "1.0", "1", "latest")...)
	all2 = append(all2, publish(600, at(600), "1.1.0", "1.1", "1", "latest")...)
	all2 = append(all2, publish(700, at(1200), "1.2.0", "1.2", "1", "latest")...)

	p2 := decide(all2, 2)
	if fmt.Sprint(ids(p2.Rescued)) != fmt.Sprint([]int64{500}) {
		t.Fatalf("rescued %v, want [500] (only version tagged 1.0)", ids(p2.Rescued))
	}
	// Nothing is deleted then: 1.0.0 is the only surviving `1.0`.
	if got := len(p2.versionsToDelete()); got != 0 {
		t.Fatalf("deleted %d versions, want 0", got)
	}
}

func TestDecideBelowWindowIsANoOp(t *testing.T) {
	var all []version
	all = append(all, publish(100, at(0), "1.0.3", "1.0", "1", "latest")...)
	all = append(all, publish(200, at(600), "1.0.4", "1.0", "1", "latest")...)
	p := decide(all, 3)
	if len(p.Drop) != 0 || len(p.versionsToDelete()) != 0 {
		t.Fatalf("deleted %v with a window larger than the package", ids(p.versionsToDelete()))
	}
	if len(p.Keep) != 2 {
		t.Fatalf("kept %d releases, want 2", len(p.Keep))
	}
}

func TestDecideDeletesOrphanFragments(t *testing.T) {
	// A fragment whose index is already gone still has to be swept once it is
	// older than the window boundary.
	var all []version
	all = append(all, publish(200, at(600), "1.0.2")...)
	all = append(all, publish(300, at(1200), "1.0.3")...)
	all = append(all, publish(400, at(1800), "1.0.4")...)
	all = append(all, version{ID: 50, Name: "sha256:orphan", CreatedAt: at(30)})

	p := decide(all, 2)
	got := ids(p.versionsToDelete())
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	want := []int64{50, 200, 201, 202, 203, 204}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("deleted %v, want %v", got, want)
	}
}

func TestDecideEmpty(t *testing.T) {
	p := decide(nil, 3)
	if len(p.Keep) != 0 || len(p.versionsToDelete()) != 0 {
		t.Fatal("empty package produced a non-empty plan")
	}
}

func TestListVersionsPaginatesAndParsesTags(t *testing.T) {
	var pages [][]map[string]any
	first := []map[string]any{}
	for i := int64(1); i <= 100; i++ {
		v := map[string]any{"id": i, "name": fmt.Sprintf("sha256:%040d", i), "created_at": at(int(i)).Format(time.RFC3339)}
		if i == 1 {
			v["metadata"] = map[string]any{"container": map[string]any{"tags": []string{"1.0.0", "latest"}}}
		}
		first = append(first, v)
	}
	pages = append(pages, first)
	pages = append(pages, []map[string]any{{"id": 101, "name": "sha256:last", "created_at": at(0).Format(time.RFC3339)}})

	var mu sync.Mutex
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/versions") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		page := r.URL.Query().Get("page")
		idx := 1
		if page == "2" {
			idx = 2
		}
		_ = json.NewEncoder(w).Encode(pages[idx-1])
	}))
	defer srv.Close()

	c := client{api: srv.URL, owner: "org", pkg: "echo-server", token: "tok", http: srv.Client()}
	vs, err := c.listVersions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 101 {
		t.Fatalf("got %d versions, want 101", len(vs))
	}
	if len(vs[0].Tags) != 2 || vs[0].Tags[0] != "1.0.0" {
		t.Fatalf("tags not parsed: %+v", vs[0])
	}
	if requests != 2 {
		t.Fatalf("made %d requests, want 2 (one per page)", requests)
	}
}

func TestDeleteVersionUsesTheOrgEndpoint(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := client{api: srv.URL, owner: "an org", pkg: "a.pkg", token: "tok", http: srv.Client()}
	if err := c.deleteVersion(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method %q, want DELETE", gotMethod)
	}
	if gotPath != "/orgs/an org/packages/container/a.pkg/versions/42" {
		t.Fatalf("path %q does not match the org-scoped endpoint", gotPath)
	}
}
