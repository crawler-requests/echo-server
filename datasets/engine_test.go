package datasets

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A tiny codec the engine tests use: values are strings, merge joins explicit
// parts in order, entries = decoded byte length. Content prefixed with "!"
// fails to decode, so tests can exercise the "skip undecodable file" path.
type strCodec struct{}

func (strCodec) Decode(data []byte, format string) (string, error) {
	if strings.HasPrefix(string(data), "!") {
		return "", fmt.Errorf("intentionally undecodable")
	}
	return string(data), nil
}
func (strCodec) Stats(s string) Stats        { return Stats{Entries: len(s)} }
func (strCodec) Merge(parts []string) string { return strings.Join(parts, "|") }

// newStr creates a registered manager with the string codec.
func newStr(t *testing.T, opts Options[string, string]) *Manager[string, string] {
	t.Helper()
	return New("t-"+t.Name(), strCodec{}, opts)
}

func TestPriorityOrderAndBuiltinLast(t *testing.T) {
	ResetRegistryForTest()
	m := newStr(t, Options[string, string]{CacheDir: t.TempDir()})
	m.SetEmbedded("e")
	lo, err := m.Upsert(ProviderConfig{Name: "lo", Kind: KindFile, Enabled: true, Priority: 1, Path: writeFile(t, "lo.txt", "L")})
	if err != nil {
		t.Fatalf("Upsert lo: %v", err)
	}
	hi, err := m.Upsert(ProviderConfig{Name: "hi", Kind: KindFile, Enabled: true, Priority: 100, Path: writeFile(t, "hi.txt", "H")})
	if err != nil {
		t.Fatalf("Upsert hi: %v", err)
	}
	_ = lo
	if got := m.Current(); got != "H|L|e" {
		t.Fatalf("Current = %q, want hi|lo|embedded", got)
	}
	_ = hi
	// Statuses come back in priority order, builtin last.
	st := m.ListStatuses()
	if len(st) != 3 || st[0].Name != "hi" || st[1].Name != "lo" || st[2].Name != "builtin" {
		t.Fatalf("order = %+v", st)
	}
}

func TestFileAndDirectoryProviders(t *testing.T) {
	ResetRegistryForTest()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "A")
	writeFile(t, filepath.Join(dir, "b.txt"), "B")
	writeFile(t, filepath.Join(dir, "notes.md"), "!not data") // skipped: undecodable
	writeFile(t, filepath.Join(dir, ".hidden"), "H")          // dotfiles skipped
	m := newStr(t, Options[string, string]{CacheDir: t.TempDir()})
	st, err := m.Upsert(ProviderConfig{Name: "dir", Kind: KindFile, Enabled: true, Priority: 1, Path: dir})
	if err != nil {
		t.Fatalf("Upsert dir: %v", err)
	}
	if st.Status != "ok" || st.Entries != 2 {
		t.Fatalf("status = %+v, want ok with 2 entries", st)
	}
	if got := m.Current(); got != "A|B" {
		t.Fatalf("Current = %q, want A|B", got)
	}

	// A missing file is rejected outright, not half-installed.
	if _, err := m.Upsert(ProviderConfig{Name: "bad", Kind: KindFile, Enabled: true, Path: filepath.Join(dir, "nope.txt")}); err == nil {
		t.Fatal("Upsert of missing file should fail")
	}
	for _, s := range m.ListStatuses() {
		if s.Name == "bad" {
			t.Fatalf("failed provider was half-installed: %+v", s)
		}
	}
	// A failed update of an existing file provider keeps the old configuration.
	if _, err := m.Upsert(ProviderConfig{Name: "dir", Kind: KindFile, Enabled: true, Path: filepath.Join(dir, "nope.txt")}); err == nil {
		t.Fatal("update to a missing path should fail")
	}
	if got := m.Current(); got != "A|B" {
		t.Fatalf("failed update changed the published value: %q", got)
	}
	st, err = m.Upsert(ProviderConfig{Name: "single", Kind: KindFile, Enabled: true, Priority: 2, Path: writeFile(t, "one.txt", "1")})
	if err != nil {
		t.Fatalf("Upsert single: %v", err)
	}
	if st.Status != "ok" || st.Entries != 1 {
		t.Fatalf("status = %+v", st)
	}
}

func TestDisabledProviderExcluded(t *testing.T) {
	ResetRegistryForTest()
	m := newStr(t, Options[string, string]{CacheDir: t.TempDir()})
	m.SetEmbedded("e")
	f := writeFile(t, "x.txt", "X")
	on, _ := m.Upsert(ProviderConfig{Name: "on", Kind: KindFile, Enabled: true, Priority: 2, Path: f})
	off, _ := m.Upsert(ProviderConfig{Name: "off", Kind: KindFile, Enabled: false, Priority: 3, Path: f})
	if on.Status != "ok" || off.Status != "disabled" {
		t.Fatalf("statuses = %+v / %+v", on, off)
	}
	if got := m.Current(); got != "X|e" {
		t.Fatalf("Current = %q, want only enabled provider", got)
	}
}

func TestUpsertValidation(t *testing.T) {
	ResetRegistryForTest()
	m := newStr(t, Options[string, string]{CacheDir: t.TempDir()})
	cases := []struct {
		name string
		cfg  ProviderConfig
	}{
		{"no name", ProviderConfig{Kind: KindFile, Path: "x"}},
		{"builtin name", ProviderConfig{Name: "builtin", Kind: KindFile, Path: "x"}},
		{"file without path", ProviderConfig{Name: "p", Kind: KindFile}},
		{"remote without url", ProviderConfig{Name: "p", Kind: KindRemote}},
		{"command without command", ProviderConfig{Name: "p", Kind: KindCommand}},
		{"bogus kind", ProviderConfig{Name: "p", Kind: Kind("magic")}},
	}
	for _, tc := range cases {
		if _, err := m.Upsert(tc.cfg); err == nil {
			t.Errorf("%s: Upsert should fail", tc.name)
		}
	}
	if err := m.Delete("builtin"); err == nil {
		t.Fatal("deleting builtin should fail")
	}
	if err := m.Delete("nope"); err == nil {
		t.Fatal("deleting unknown provider should fail")
	}
}

func TestRemoteSyncETag(t *testing.T) {
	ResetRegistryForTest()
	const payload = "remote-data-v1"
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		fmt.Fprint(w, payload)
	}))
	defer srv.Close()

	m := newStr(t, Options[string, string]{CacheDir: t.TempDir()})
	st, err := m.Upsert(ProviderConfig{Name: "cloud", Kind: KindRemote, Enabled: true, Priority: 1, URL: srv.URL})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if st.Status != "ok" {
		t.Fatalf("status = %+v", st)
	}
	if got := m.Current(); got != payload {
		t.Fatalf("Current = %q, want %q", got, payload)
	}
	if err := m.Sync("cloud"); err != nil {
		t.Fatal("Sync should succeed")
	}
	if c := calls.Load(); c != 2 {
		t.Fatalf("expected 2 fetches (200 then 304), got %d", c)
	}
}

func TestRemoteCachedCopySurvivesRestartAndFailure(t *testing.T) {
	ResetRegistryForTest()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, "fresh")
	}))
	cacheDir := t.TempDir()
	m := newStr(t, Options[string, string]{CacheDir: cacheDir})
	if _, err := m.Upsert(ProviderConfig{Name: "cloud", Kind: KindRemote, Enabled: true, URL: srv.URL}); err != nil {
		t.Fatal(err)
	}
	if got := m.Current(); got != "fresh" {
		t.Fatalf("Current = %q", got)
	}
	srv.Close() // the provider is now unreachable

	// A refresh against the dead endpoint fails in the status but keeps the
	// previously loaded value. (Sync itself returns nil: failure is reportable
	// through the status, and the cached value stays in effect.)
	if err := m.Sync("cloud"); err != nil {
		t.Fatalf("Sync should not error on fetch failure, got %v", err)
	}
	if got := m.Current(); got != "fresh" {
		t.Fatalf("Current after failed sync = %q, want cached 'fresh'", got)
	}
	if st := m.ListStatuses(); len(st) != 1 || st[0].Status != "error" {
		t.Fatalf("statuses = %+v, want error", st)
	}

	// Restart: a fresh manager, same cache dir, config re-declared. It loads
	// the cached copy without touching the network.
	cfgJSON, _ := json.Marshal([]ProviderConfig{{Name: "cloud", Kind: KindRemote, Enabled: true, URL: "http://127.0.0.1:1/dead"}})
	m2 := newStr(t, Options[string, string]{
		CacheDir:   cacheDir,
		LoadConfig: func() (string, string) { return string(cfgJSON), "" },
	})
	m2.Init()
	if got := m2.Current(); got != "fresh" {
		t.Fatalf("restart Current = %q, want cached 'fresh'", got)
	}
	// Only the original fetch reached the (now dead) server; the failed refresh
	// and the restart-from-cache paths never touched it.
	if c := calls.Load(); c != 1 {
		t.Fatalf("network hits: %d, want 1 (the initial fetch only)", c)
	}
}

func TestCommandProvider(t *testing.T) {
	ResetRegistryForTest()
	m := newStr(t, Options[string, string]{CacheDir: t.TempDir()})
	st, err := m.Upsert(ProviderConfig{Name: "gen", Kind: KindCommand, Enabled: true, Command: "printf 'generated\\n'"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if st.Status != "ok" {
		t.Fatalf("status = %+v", st)
	}
	if got := m.Current(); got != "generated\n" {
		t.Fatalf("Current = %q", got)
	}
	if st.LastSync == "" {
		t.Fatal("command provider should record a last sync time")
	}

	// A failing command surfaces in the status and keeps the old value.
	if _, err := m.Upsert(ProviderConfig{Name: "gen", Kind: KindCommand, Enabled: true, Command: "printf 'v2\\n'"}); err != nil {
		t.Fatal(err)
	}
	failSt, err := m.Upsert(ProviderConfig{Name: "gen", Kind: KindCommand, Enabled: true, Command: "exit 3"})
	if err != nil {
		t.Fatalf("Upsert with failing command should not error (sync is best-effort): %v", err)
	}
	if failSt.Status != "error" {
		t.Fatalf("status = %+v, want error", failSt)
	}
	if got := m.Current(); got != "v2\n" {
		t.Fatalf("Current after failed rerun = %q, want old value kept", got)
	}
}

func TestCustomScheme(t *testing.T) {
	ResetRegistryForTest()
	RegisterScheme("stub", func(url, etag string) (FetchResult, error) {
		if etag != "" {
			return FetchResult{NotModified: true, ETag: etag}, nil
		}
		return FetchResult{Data: []byte("stub-data"), ETag: "e1"}, nil
	})
	m := newStr(t, Options[string, string]{CacheDir: t.TempDir()})
	st, err := m.Upsert(ProviderConfig{Name: "s3", Kind: KindRemote, Enabled: true, URL: "stub://bucket/lib"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if st.Status != "ok" || m.Current() != "stub-data" {
		t.Fatalf("status=%v Current=%q", st, m.Current())
	}
	// An unregistered scheme renders the provider in error state at sync time.
	_, err = m.Upsert(ProviderConfig{Name: "unknown", Kind: KindRemote, Enabled: true, URL: "nope://x"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range m.ListStatuses() {
		if s.Name == "unknown" && s.Status != "error" {
			t.Fatalf("unknown scheme should error, got %+v", s)
		}
	}
	if fetcherFor("stub://x") == nil {
		t.Fatal("registered scheme should resolve")
	}
}

func TestStampAndOnChange(t *testing.T) {
	ResetRegistryForTest()
	var changed atomic.Pointer[string]
	m := New("stamp-"+t.Name(), strCodec{}, Options[string, string]{
		CacheDir: t.TempDir(),
		Stamp:    func(v, name string) string { return name + ":" + v },
		OnChange: func(v string) { val := v; changed.Store(&val) },
	})
	m.SetEmbedded("e")
	if got := *changed.Load(); got != "e" {
		t.Fatalf("OnChange embedded = %q", got)
	}
	_, _ = m.Upsert(ProviderConfig{Name: "p", Kind: KindFile, Enabled: true, Path: writeFile(t, "v.txt", "V")})
	if got := *changed.Load(); got != "p:V|e" {
		t.Fatalf("OnChange = %q, want stamp applied", got)
	}
}

func TestPersistenceThroughSaver(t *testing.T) {
	ResetRegistryForTest()
	var saved [][]ProviderConfig
	m := newStr(t, Options[string, string]{
		CacheDir: t.TempDir(),
		Saver:    func(cfgs []ProviderConfig) error { saved = append(saved, cfgs); return nil },
	})
	m.SetEmbedded("e")
	_, _ = m.Upsert(ProviderConfig{Name: "a", Kind: KindFile, Path: writeFile(t, "a.txt", "A"), Priority: 5})
	_, _ = m.Upsert(ProviderConfig{Name: "b", Kind: KindFile, Path: writeFile(t, "b.txt", "B"), Priority: 1})
	_ = m.Delete("a")
	if len(saved) != 3 {
		t.Fatalf("saver called %d times, want 3", len(saved))
	}
	last := saved[len(saved)-1]
	if len(last) != 1 || last[0].Name != "b" {
		t.Fatalf("final persisted list = %+v", last)
	}
}

func TestLoadFromConfigPersistedThenExtra(t *testing.T) {
	ResetRegistryForTest()
	dir := t.TempDir()
	a := writeFile(t, filepath.Join(dir, "a.txt"), "A")
	b := writeFile(t, filepath.Join(dir, "b.txt"), "B")
	persisted, _ := json.Marshal([]ProviderConfig{{Name: "a", Kind: KindFile, Enabled: true, Path: a}})
	extra, _ := json.Marshal([]ProviderConfig{{Name: "b", Kind: KindFile, Enabled: true, Path: b}})
	m := newStr(t, Options[string, string]{
		CacheDir:   t.TempDir(),
		LoadConfig: func() (string, string) { return string(persisted), string(extra) },
	})
	m.SetEmbedded("e")
	m.Init()
	if got := m.Current(); got != "A|B|e" {
		t.Fatalf("Current = %q, want A|B|e", got)
	}
	// Bad JSON is skipped without a crash.
	m2 := newStr(t, Options[string, string]{
		LoadConfig: func() (string, string) { return "not json", "" },
	})
	m2.Init()
}

// TestETagPersistsAcrossRestart: the cached validator must survive a restart so
// the first refresh is a conditional request (304) rather than a full download.
func TestETagPersistsAcrossRestart(t *testing.T) {
	ResetRegistryForTest()
	cacheDir := t.TempDir()
	const payload = "cloud-payload"
	var calls atomic.Int32
	var sawIfNoneMatch atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		sawIfNoneMatch.Store(r.Header.Get("If-None-Match"))
		if r.Header.Get("If-None-Match") == `"e1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"e1"`)
		fmt.Fprint(w, payload)
	}))
	defer srv.Close()

	cfg := ProviderConfig{Name: "cloud", Kind: KindRemote, Enabled: true, URL: srv.URL, RefreshMin: 30}
	m1 := newStr(t, Options[string, string]{CacheDir: cacheDir})
	if _, err := m1.Upsert(cfg); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("initial fetch calls = %d", calls.Load())
	}

	persisted, _ := json.Marshal([]ProviderConfig{cfg})
	m2 := newStr(t, Options[string, string]{
		CacheDir:   cacheDir,
		LoadConfig: func() (string, string) { return string(persisted), "" },
	})
	m2.Init()
	if got := m2.Current(); got != payload {
		t.Fatalf("cache did not load after restart: %q", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("startup refresh did not run (calls=%d)", calls.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := sawIfNoneMatch.Load(); got != `"e1"` {
		t.Fatalf("startup refresh sent If-None-Match %v, want cached ETag", got)
	}
	if got := m2.Current(); got != payload {
		t.Fatalf("304 must keep the cached value, got %q", got)
	}
	if st := m2.ListStatuses()[0]; st.Status != "ok" {
		t.Fatalf("status after 304 = %+v", st)
	}
}

func TestRemoteAuthHeadersAndMasking(t *testing.T) {
	ResetRegistryForTest()
	var gotAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		fmt.Fprint(w, "private")
	}))
	defer srv.Close()

	m := newStr(t, Options[string, string]{CacheDir: t.TempDir()})
	st, err := m.Upsert(ProviderConfig{
		Name: "cloud", Kind: KindRemote, Enabled: true, URL: srv.URL,
		Headers: map[string]string{"Authorization": "Bearer secret"},
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if gotAuth.Load() != "Bearer secret" {
		t.Fatalf("server saw Authorization %q", gotAuth.Load())
	}
	// Status must reveal that a header exists but not its value.
	if st.Headers["Authorization"] != MaskedHeader {
		t.Fatalf("status headers = %v, want masked", st.Headers)
	}
	// Sending the mask back (an edit that did not retype the token) keeps the
	// stored secret rather than overwriting it with "***".
	if err := m.Sync("cloud"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Upsert(ProviderConfig{
		Name: "cloud", Kind: KindRemote, Enabled: true, URL: srv.URL,
		Headers: map[string]string{"Authorization": MaskedHeader},
	}); err != nil {
		t.Fatal(err)
	}
	if gotAuth.Load() != "Bearer secret" {
		t.Fatalf("after masked update server saw %q", gotAuth.Load())
	}
	// An explicit new value replaces it.
	if _, err := m.Upsert(ProviderConfig{
		Name: "cloud", Kind: KindRemote, Enabled: true, URL: srv.URL,
		Headers: map[string]string{"Authorization": "Bearer rotated"},
	}); err != nil {
		t.Fatal(err)
	}
	if gotAuth.Load() != "Bearer rotated" {
		t.Fatalf("after rotation server saw %q", gotAuth.Load())
	}
}

// TestURLUserinfoMaskedAndPreserved: credentials embedded in the URL reach the
// server as Basic auth, are masked in status, and survive a masked edit.
func TestURLUserinfoMaskedAndPreserved(t *testing.T) {
	ResetRegistryForTest()
	var user, pass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ = r.BasicAuth()
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	withCreds := strings.Replace(srv.URL, "http://", "http://alice:s3cret@", 1)
	m := newStr(t, Options[string, string]{CacheDir: t.TempDir()})
	st, err := m.Upsert(ProviderConfig{Name: "cloud", Kind: KindRemote, Enabled: true, URL: withCreds})
	if err != nil {
		t.Fatal(err)
	}
	if user != "alice" || pass != "s3cret" {
		t.Fatalf("server basic auth = %q/%q", user, pass)
	}
	if strings.Contains(st.URL, "s3cret") || !strings.Contains(st.URL, MaskedHeader+"@") {
		t.Fatalf("status URL not masked: %q", st.URL)
	}
	// Sending the masked URL back keeps the stored credentials.
	masked := strings.Replace(withCreds, "alice:s3cret", MaskedHeader, 1)
	user, pass = "", ""
	if _, err := m.Upsert(ProviderConfig{Name: "cloud", Kind: KindRemote, Enabled: true, URL: masked}); err != nil {
		t.Fatal(err)
	}
	if user != "alice" || pass != "s3cret" {
		t.Fatalf("after masked update server basic auth = %q/%q", user, pass)
	}
}

func TestFileHotReload(t *testing.T) {
	ResetRegistryForTest()
	path := writeFile(t, "lib.txt", "v1")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	m := newStr(t, Options[string, string]{CacheDir: t.TempDir()})
	if _, err := m.Upsert(ProviderConfig{
		Name: "local", Kind: KindFile, Enabled: true, Path: path, RefreshMin: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := m.Current(); got != "v1" {
		t.Fatalf("Current = %q", got)
	}
	writeFile(t, path, "v2")
	// Ensure a distinct mtime even on coarse filesystems.
	newer := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, newer, newer); err != nil {
		t.Fatal(err)
	}
	m.syncDue()
	if got := m.Current(); got != "v2" {
		t.Fatalf("after reload Current = %q, want v2", got)
	}
	// Unchanged file: no reload, status stays ok.
	m.syncDue()
	if got := m.ListStatuses()[0].Status; got != "ok" {
		t.Fatalf("status = %q", got)
	}
	// A manual Sync reloads even when the timestamp did not move.
	writeFile(t, path, "v3")
	if err := os.Chtimes(path, newer, newer); err != nil {
		t.Fatal(err)
	}
	if err := m.Sync("local"); err != nil {
		t.Fatalf("Sync(file): %v", err)
	}
	if got := m.Current(); got != "v3" {
		t.Fatalf("after manual reload Current = %q, want v3", got)
	}
}

func TestHotReloadDirectory(t *testing.T) {
	ResetRegistryForTest()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "A")
	m := newStr(t, Options[string, string]{CacheDir: t.TempDir()})
	if _, err := m.Upsert(ProviderConfig{
		Name: "dir", Kind: KindFile, Enabled: true, Path: dir, RefreshMin: 1,
	}); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "b.txt"), "B")
	m.syncDue()
	if got := m.Current(); got != "A|B" {
		t.Fatalf("Current = %q, want A|B", got)
	}
}

// TestRefreshOutsideLock proves a slow fetch does not block reads of the
// manager state.
func TestRefreshOutsideLock(t *testing.T) {
	ResetRegistryForTest()
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		fmt.Fprint(w, "slow")
	}))
	defer srv.Close()

	m := newStr(t, Options[string, string]{})
	// Insert without triggering the network: the provider starts disabled-remote
	// but Sync below performs the fetch.
	m.mu.Lock()
	p := &provider[string]{cfg: ProviderConfig{
		Name: "slow", Kind: KindRemote, Enabled: true, URL: srv.URL,
	}}
	p.status = "empty"
	m.providers["slow"] = p
	m.order = append(m.order, "slow")
	m.mu.Unlock()

	go m.refresh("slow")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh never reached the server")
	}
	// The fetch is blocked inside the handler: status reads must still return.
	done := make(chan struct{})
	go func() { m.ListStatuses(); m.Current(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ListStatuses blocked behind a network fetch")
	}
	close(release)
	// Wait for the refresh to apply.
	deadline := time.Now().Add(5 * time.Second)
	for m.Current() != "slow" {
		if time.Now().After(deadline) {
			t.Fatal("refresh result never applied")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSupersededRefreshDiscarded checks that reconfiguring a provider while a
// fetch is in flight drops the stale result instead of republishing it.
func TestSupersededRefreshDiscarded(t *testing.T) {
	ResetRegistryForTest()
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		fmt.Fprint(w, "stale")
	}))
	defer srv.Close()

	m := newStr(t, Options[string, string]{CacheDir: t.TempDir()})
	m.mu.Lock()
	p := &provider[string]{cfg: ProviderConfig{Name: "p", Kind: KindRemote, Enabled: true, URL: srv.URL}}
	m.providers["p"] = p
	m.order = append(m.order, "p")
	m.mu.Unlock()

	go m.refresh("p")
	<-entered
	// Replace the provider with a file source while the HTTP fetch is blocked.
	path := writeFile(t, "local.txt", "fresh")
	if _, err := m.Upsert(ProviderConfig{
		Name: "p", Kind: KindFile, Enabled: true, Path: path,
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	time.Sleep(100 * time.Millisecond) // let the stale fetch finish and be dropped
	if got := m.Current(); got != "fresh" {
		t.Fatalf("Current = %q, want fresh (stale HTTP result must be discarded)", got)
	}
}

// writeFile writes a file (absolute, or under a fresh temp dir) and returns
// its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := name
	if !filepath.IsAbs(path) {
		path = filepath.Join(t.TempDir(), filepath.Base(name))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
