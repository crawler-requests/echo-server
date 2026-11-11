package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/crawler-requests/echo-server/datasets"
)

// resetJa4 tears down and rebuilds the "ja4" dataset so every test starts from
// a clean provider list (embedded snapshot only). Other datasets are untouched.
func resetJa4(t *testing.T) {
	t.Helper()
	datasets.ResetRegistryForTest()
	initJA4Dataset()
}

// providerStatus returns the live status for a provider by name.
func providerStatus(t *testing.T, mgr datasets.Dataset, name string) datasets.ProviderStatus {
	t.Helper()
	for _, st := range mgr.ListStatuses() {
		if st.Name == name {
			return st
		}
	}
	t.Fatalf("provider %q not found in %v", name, mgr.Name())
	return datasets.ProviderStatus{}
}

// libraryJSONFor builds a data/ja4db.json-contract library for a single
// fingerprint whose UA evidence names the given client.
func libraryJSONFor(fp, ua string, count uint64) string {
	doc := map[string]any{
		"meta": map[string]any{
			"source": "test library", "exported": "2026-01-01",
			"entries": 1, "observations": count,
		},
		"ja4": map[string]any{
			fp: map[string]any{
				"n":   count,
				"uas": [][2]any{{ua, count}},
			},
		},
	}
	b, _ := json.Marshal(doc)
	return string(b)
}

func writeTempLibrary(t *testing.T, fp, ua string, count uint64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lib.json")
	if err := os.WriteFile(path, []byte(libraryJSONFor(fp, ua, count)), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A custom file library must win over the embedded snapshot by priority, and
// matches must be attributed to the provider that supplied them.
func TestJA4Dataset_FileJSON_OverridesBuiltin(t *testing.T) {
	resetJa4(t)
	const fp = "t13i3111h2_e8f1e7e78f70_b26ce05bbdd6"
	path := writeTempLibrary(t, fp, "curl/8.5.0", 9)

	st, err := ja4Mgr.Upsert(datasets.ProviderConfig{
		Name: "custom", Kind: datasets.KindFile, Enabled: true, Priority: 10, Path: path,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if st.Status != "ok" || st.Entries != 1 {
		t.Fatalf("status = %+v, want ok with 1 entry", st)
	}

	m := lookupJA4(fp)
	if m == nil {
		t.Fatalf("lookupJA4(%s) = nil", fp)
	}
	if m.Name != "curl" || m.Provider != "custom" {
		t.Fatalf("match = %+v, want curl via provider custom", m)
	}

	// The generic list endpoint exposes the same info.
	sts := ja4Mgr.ListStatuses()
	if len(sts) != 2 || sts[0].Name != "custom" || sts[1].Name != "builtin" {
		t.Fatalf("provider order = %+v", sts)
	}
	if sts[0].Source == "" || sts[0].LoadedAt == "" {
		t.Fatalf("status missing source/loaded_at: %+v", sts[0])
	}
}

// A community CSV (the ja4db-export snapshot format) must import like a
// freshly generated JSON library.
func TestJA4Dataset_FileCSV(t *testing.T) {
	resetJa4(t)
	csv := "ja4_fingerprint,application,library,user_agent_string,verified,observation_count\n" +
		"t13d1516h2_8daaf6152771_d8a2da3f94cd,Chrome,,Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/142.0.0.0 Safari/537.36,true,120\n" +
		"t13d9999zz_aaaaaaaaaaaa_bbbbbbbbbbbb,,CustomLib,,false,2\n"
	path := filepath.Join(t.TempDir(), "fp.csv")
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := ja4Mgr.Upsert(datasets.ProviderConfig{
		Name: "csv", Kind: datasets.KindFile, Enabled: true, Priority: 10, Path: path,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if st.Status != "ok" || st.Entries != 2 {
		t.Fatalf("status = %+v, want ok with 2 entries", st)
	}

	m := lookupJA4("t13d1516h2_8daaf6152771_d8a2da3f94cd")
	if m == nil || m.Name != "Chrome" || m.Provider != "csv" {
		t.Fatalf("match = %+v, want Chrome via csv", m)
	}
}

// Remote provider: first sync fetches the library and sets an ETag; a second
// sync with an unchanged library gets a 304 and reloads nothing.
func TestJA4Dataset_RemoteSyncAndETag(t *testing.T) {
	resetJa4(t)
	const fp = "t13i3111h2_e8f1e7e78f70_b26ce05bbdd6"
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		if r.Header.Get("If-None-Match") == `"v9"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v9"`)
		fmt.Fprint(w, libraryJSONFor(fp, "curl/8.5.0", 9))
	}))
	defer srv.Close()

	st, err := ja4Mgr.Upsert(datasets.ProviderConfig{
		Name: "cloud", Kind: datasets.KindRemote, Enabled: true, Priority: 10,
		URL: srv.URL, Format: "json",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if st.Status != "ok" || st.Source == "" {
		t.Fatalf("status = %+v", st)
	}
	if m := lookupJA4(fp); m == nil || m.Provider != "cloud" {
		t.Fatalf("match = %+v, want cloud", m)
	}
	if st.LastSync == "" {
		t.Fatal("remote provider should record last_sync")
	}

	if err := ja4Mgr.Sync("cloud"); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	mu.Lock()
	c := calls
	mu.Unlock()
	if c != 2 {
		t.Fatalf("expected 2 fetches (200 then 304), got %d", c)
	}
}

// Remote provider caching: the synced library is cached on disk; a refresh
// against a dead server keeps the old value and reports an error status.
func TestJA4Dataset_RemoteCacheFallback(t *testing.T) {
	resetJa4(t)
	const fp = "t13i3111h2_e8f1e7e78f70_b26ce05bbdd6"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, libraryJSONFor(fp, "curl/8.5.0", 9))
	}))
	st, err := ja4Mgr.Upsert(datasets.ProviderConfig{
		Name: "cloud", Kind: datasets.KindRemote, Enabled: true, Priority: 10,
		URL: srv.URL, Format: "json",
	})
	if err != nil || st.Status != "ok" {
		t.Fatalf("Upsert: %v status=%+v", err, st)
	}
	srv.Close()

	if err := ja4Mgr.Sync("cloud"); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	st = providerStatus(t, ja4Mgr, "cloud")
	if st.Status != "error" {
		t.Fatalf("status = %+v, want error after server died", st)
	}
	if m := lookupJA4(fp); m == nil || m.Name != "curl" {
		t.Fatalf("match = %+v, want cached value still effective", m)
	}
}

func TestJA4Dataset_UpsertValidation(t *testing.T) {
	resetJa4(t)
	cases := []datasets.ProviderConfig{
		{Kind: datasets.KindFile, Path: "/x"},                  // no name
		{Name: "builtin", Kind: datasets.KindFile, Path: "/x"}, // reserved
		{Name: "p", Kind: datasets.KindFile},                   // no path
		{Name: "p", Kind: datasets.KindRemote},                 // no url
		{Name: "p", Kind: datasets.KindCommand},                // no command
		{Name: "p", Kind: datasets.Kind("bogus")},              // bad kind
	}
	for i, cfg := range cases {
		if _, err := ja4Mgr.Upsert(cfg); err == nil {
			t.Errorf("case %d: Upsert(%+v) should fail", i, cfg)
		}
	}
	if err := ja4Mgr.Delete("builtin"); err == nil {
		t.Fatal("deleting builtin should fail")
	}
	if err := ja4Mgr.Delete("nope"); err == nil {
		t.Fatal("deleting missing provider should fail")
	}
}

// Higher priority decides; deleting a provider falls back to the next one,
// then to the embedded snapshot.
func TestJA4Dataset_PriorityAndDelete(t *testing.T) {
	resetJa4(t)
	const fp = "t13d16162h2_8daaf6152771_1c2a5a7c6b8c"
	lo := writeTempLibrary(t, fp, "curl/8.5.0", 5)
	hi := writeTempLibrary(t, fp, "wget/1.21", 3)

	if _, err := ja4Mgr.Upsert(datasets.ProviderConfig{Name: "low", Kind: datasets.KindFile, Enabled: true, Priority: 1, Path: lo}); err != nil {
		t.Fatal(err)
	}
	if _, err := ja4Mgr.Upsert(datasets.ProviderConfig{Name: "high", Kind: datasets.KindFile, Enabled: true, Priority: 10, Path: hi}); err != nil {
		t.Fatal(err)
	}
	m := lookupJA4(fp)
	if m == nil || m.Name != "wget" || m.Provider != "high" {
		t.Fatalf("match = %+v, want wget via high", m)
	}

	if err := ja4Mgr.Delete("high"); err != nil {
		t.Fatal(err)
	}
	m = lookupJA4(fp)
	if m == nil || m.Provider != "low" || m.Name != "curl" {
		t.Fatalf("match = %+v, want curl via low", m)
	}

	if err := ja4Mgr.Delete("low"); err != nil {
		t.Fatal(err)
	}
	if m := lookupJA4(fp); m != nil {
		t.Fatalf("match = %+v, want nil (embedded does not know this fp)", m)
	}
	if len(ja4Mgr.ListStatuses()) != 1 || ja4Mgr.ListStatuses()[0].Name != "builtin" {
		t.Fatalf("providers after deletes = %+v", ja4Mgr.ListStatuses())
	}
}

// The lookup path must stay lock-free and crash-free while providers are being
// added/removed underneath it.
func TestJA4Dataset_ConcurrentLookup(t *testing.T) {
	resetJa4(t)
	fp := "t13d1616h2_8daaf6152771_1c2a5a7c6b8c"
	lib := writeTempLibrary(t, fp, "curl/8.5.0", 3)
	done := make(chan struct{})
	go func() { // churn providers while readers run
		defer close(done)
		for i := 0; i < 30; i++ {
			name := fmt.Sprintf("p%d", i%3)
			_ = ja4Mgr.Delete(name)
			_, _ = ja4Mgr.Upsert(datasets.ProviderConfig{Name: name, Kind: datasets.KindFile, Enabled: true, Priority: i % 5, Path: lib})
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
			_ = lookupJA4(fp)
			_ = lookupJA4("t13d9999zz_aaaaaaaaaaaa_bbbbbbbbbbbb")
		}
	}
}

// A library matching only on the JA4 prefix must still resolve, with the
// prefix-match note set.
func TestJA4Dataset_PrefixFallback(t *testing.T) {
	resetJa4(t)
	const fp = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	const newer = "t13d1516h2_8daaf6152771_d8a2da3f94cd_newerhash1"
	path := writeTempLibrary(t, fp, "Chrome/142.0.0.0", 12)
	_, err := ja4Mgr.Upsert(datasets.ProviderConfig{Name: "c", Kind: datasets.KindFile, Enabled: true, Priority: 1, Path: path})
	if err != nil {
		t.Fatal(err)
	}
	m := lookupJA4(newer)
	if m == nil || m.Name != "Chrome" || !strings.Contains(m.Note, "prefix") {
		t.Fatalf("match = %+v, want prefix-based Chrome", m)
	}
}

// Environment seeding: DATASET_PROVIDERS (object keyed by dataset) and the
// legacy JA4_PROVIDERS both feed the "ja4" dataset.
func TestJA4Dataset_EnvConfig(t *testing.T) {
	raw := `/tmp/env-lib-0.json`
	defer os.Unsetenv("JA4_PROVIDERS")
	defer os.Unsetenv("DATASET_PROVIDERS")

	// Legacy single-dataset key.
	os.Setenv("JA4_PROVIDERS", `[{"name":"env-a","kind":"file","path":"`+raw+`"}]`)
	os.Setenv("DATASET_PROVIDERS", ``)
	if got := envDatasetConfig("ja4"); !strings.Contains(got, "env-a") {
		t.Fatalf("JA4_PROVIDERS not read: %s", got)
	}
	// Object keyed by dataset name.
	os.Setenv("DATASET_PROVIDERS", `{"ja4":[{"name":"env-b","kind":"file","path":"`+raw+`"}],"datacenter_cidr":[]}`)
	if got := envDatasetConfig("ja4"); !strings.Contains(got, "env-b") {
		t.Fatalf("DATASET_PROVIDERS not read: %s", got)
	}
	// Another dataset key is reachable (here an explicit empty list).
	if got := envDatasetConfig("datacenter_cidr"); got != "[]" {
		t.Fatalf("other dataset not read: %q, want []", got)
	}
}

func TestJA4Provider_SafeName(t *testing.T) {
	cases := map[string]string{
		"my-cloud-lib": "my-cloud-lib",
		"a/b\\c:d*e?":  "a_b_c_d_e_",
		"中文库":          "___",
	}
	for in, want := range cases {
		if got := safeName(in); got != want {
			t.Errorf("safeName(%q) = %q, want %q", in, got, want)
		}
	}
}
