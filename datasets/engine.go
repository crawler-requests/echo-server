// Package datasets is a generic, pluggable data-source ("provider") engine.
//
// Every data set the server needs — the JA4 fingerprint library, datacenter
// CIDR ranges, residential-proxy exits, hosting-brand keywords, and any set an
// embedder adds — is described by one Dataset, and that Dataset is assembled
// from a priority-ordered list of providers:
//
//	kind      source                                        refresh
//	embedded  compiled into the binary (always the fallback) never
//	file      a local file or directory (mounted data dir)   optional interval
//	          every decodable file inside a dir is merged     (mtime watch)
//	remote    an HTTP(S) URL (or any registered scheme)      optional interval
//	          + on-disk cache and ETag (survive restarts)    + manual sync
//	command   stdout of a local command                      optional interval
//	          (let a user implement their own source in any language)
//
// Providers are consulted highest priority first; the dataset's Codec decides
// how the per-provider values combine into the runtime value (JA4 keeps an
// ordered list of libraries, CIDR sets take the union, keywords concatenate).
// The combined value is immutable and published through an atomic pointer, so
// the query path never takes a lock: changes rebuild a fresh value and swap it.
//
// Extensibility is the point:
//   - RegisterScheme adds a URL scheme (s3://, gs://, an internal artifact
//     store, …) usable by any "remote" provider.
//   - New creates (and registers) a whole new data set from an embedder.
//   - The "command" kind needs no Go: any script that prints data on stdout.
//
// Configuration persistence is delegated to the host through Options.Saver /
// Options.LoadConfig; this package never touches storage itself.
package datasets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Kind is how a provider obtains its data.
type Kind string

const (
	KindEmbedded Kind = "embedded" // compiled in; builtin provider, immutable
	KindFile     Kind = "file"     // local file or directory
	KindRemote   Kind = "remote"   // fetched over a URL scheme (http/https by default)
	KindCommand  Kind = "command"  // stdout of a local shell command
)

// ProviderConfig is the persisted, user-editable description of one provider.
type ProviderConfig struct {
	Name       string            `json:"name"`
	Kind       Kind              `json:"kind"`
	Enabled    bool              `json:"enabled"`
	Priority   int               `json:"priority"`              // higher wins; embedded is always last
	Path       string            `json:"path,omitempty"`        // file kind (file or directory)
	URL        string            `json:"url,omitempty"`         // remote kind
	Headers    map[string]string `json:"headers,omitempty"`     // remote kind: extra HTTP request headers (auth tokens)
	Command    string            `json:"command,omitempty"`     // command kind
	Format     string            `json:"format,omitempty"`      // optional decode hint ("json"/"csv"/"lines")
	RefreshMin int               `json:"refresh_min,omitempty"` // minutes; remote/command = sync, file = mtime watch; 0 = manual
}

// ProviderStatus is the API view of a provider: config plus live state.
type ProviderStatus struct {
	ProviderConfig
	Builtin      bool   `json:"builtin"`
	Status       string `json:"status"` // ok | error | empty | disabled
	Error        string `json:"error,omitempty"`
	Entries      int    `json:"entries"`
	Observations uint64 `json:"observations"`
	Source       string `json:"source,omitempty"`
	Exported     string `json:"exported,omitempty"`
	LastSync     string `json:"last_sync,omitempty"`
	LoadedAt     string `json:"loaded_at,omitempty"`
}

// Stats summarizes a provider value for the admin UI.
type Stats struct {
	Entries      int
	Observations uint64
	Source       string
	Exported     string
}

// Codec tells the engine how to turn one provider payload into a value, how to
// summarize it, and how to combine all providers' values into the runtime
// value the application queries. Merge receives values in provider priority
// order (highest first, embedded last) so order-sensitive sets (JA4 libraries)
// work naturally.
type Codec[V, R any] interface {
	Decode(data []byte, format string) (V, error)
	Stats(V) Stats
	Merge(parts []V) R
}

// Fetcher performs one remote fetch. Implementations supporting conditional
// requests honor the previous ETag and report NotModified.
type Fetcher func(url, etag string) (FetchResult, error)

// FetchResult is one remote fetch outcome.
type FetchResult struct {
	Data        []byte
	NotModified bool
	ETag        string
}

var (
	schemesMu sync.RWMutex
	schemes   = map[string]Fetcher{"http": httpFetch, "https": httpFetch}
)

// RegisterScheme adds a URL scheme a "remote" provider can use: the part
// before "://" (e.g. "s3", "gs", "artifact"). Embedders call this from init to
// plug their own transport; users then configure remote providers normally.
func RegisterScheme(scheme string, f Fetcher) {
	scheme = strings.ToLower(strings.TrimSuffix(scheme, "://"))
	if scheme == "" || f == nil {
		return
	}
	schemesMu.Lock()
	schemes[scheme] = f
	schemesMu.Unlock()
}

func fetcherFor(rawURL string) Fetcher {
	i := strings.Index(rawURL, "://")
	if i <= 0 {
		return httpFetch // tolerate bare hosts
	}
	schemesMu.RLock()
	f := schemes[strings.ToLower(rawURL[:i])]
	schemesMu.RUnlock()
	return f
}

// maxFetchBytes caps any single provider payload.
const maxFetchBytes = 64 << 20

// httpFetch is the default http/https fetcher with ETag revalidation.
func httpFetch(url, etag string) (FetchResult, error) {
	return httpFetchWithHeaders(url, etag, nil)
}

// httpFetchWithHeaders fetches an HTTP(S) URL with optional request headers
// (e.g. Authorization for a private cloud library). ETag values from the
// server are captured for the next conditional request.
func httpFetchWithHeaders(url, etag string, headers map[string]string) (FetchResult, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return FetchResult{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := sharedClient.Do(req)
	if err != nil {
		return FetchResult{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return FetchResult{NotModified: true, ETag: etag}, nil
	case http.StatusOK:
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
		if err != nil {
			return FetchResult{}, err
		}
		return FetchResult{Data: data, ETag: resp.Header.Get("ETag")}, nil
	default:
		return FetchResult{}, fmt.Errorf("HTTP %s", resp.Status)
	}
}

var sharedClient = &http.Client{Timeout: 15 * time.Second}

// MaskedHeader is what a status report shows in place of a header value.
const MaskedHeader = "***"

// maskHeaderValues reports which headers exist without revealing secrets.
// A nil map stays nil so JSON omits the field entirely.
func maskHeaderValues(h map[string]string) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k := range h {
		out[k] = MaskedHeader
	}
	return out
}

// provider is the runtime state of one configured provider. A provider can
// contribute several parts (one per file in a directory).
type provider[V any] struct {
	cfg      ProviderConfig
	builtin  bool
	parts    []V
	status   string
	errMsg   string
	source   string
	exported string
	lastSync time.Time
	loadedAt time.Time
	etag     string

	// gen changes whenever the configuration is replaced; an in-flight
	// background fetch compares it on return and discards a stale result.
	gen uint64
	// syncSeq identifies the in-flight refresh so a superseded one cannot
	// clear the syncing flag of its successor.
	syncSeq uint64
	syncing bool
	// mtime is the newest modification time seen for a file/directory
	// provider; the watch loop reloads when it changes.
	mtime time.Time
	// lastCheck is when the watch loop last stat'ed a file provider, so a large
	// directory is not scanned on every tick.
	lastCheck time.Time
}

// Manager owns one data set's providers and its published runtime value.
type Manager[V, R any] struct {
	name        string
	description string
	codec       Codec[V, R]
	cacheDir    string
	saver       func([]ProviderConfig) error
	loadConfig  func() (persisted, extra string)
	stamp       func(V, string) V
	onChange    func(R)

	mu         sync.Mutex
	hasBuiltin bool
	providers  map[string]*provider[V]
	order      []string
	built      atomic.Pointer[R]
}

// Options configures a Manager.
type Options[V, R any] struct {
	Description string
	CacheDir    string // remote/command caches land in <CacheDir>/<dataset>/<provider>.data
	// Saver persists the full provider list after any change. Optional.
	Saver func([]ProviderConfig) error
	// LoadConfig returns the persisted config JSON and an optional extra JSON
	// (e.g. from the environment) applied after it. Optional.
	LoadConfig func() (persisted, extra string)
	// Stamp, if set, is applied to every decoded value with its provider's
	// name, so values can carry attribution (e.g. "which library matched").
	Stamp func(v V, providerName string) V
	// OnChange, if set, receives the newly published runtime value after every
	// rebuild. It runs under the manager lock, so it must not call back into
	// the manager and should be cheap (typically an atomic store).
	OnChange func(v R)
}

// New creates and registers a data set.
func New[V, R any](name string, codec Codec[V, R], opts Options[V, R]) *Manager[V, R] {
	m := &Manager[V, R]{
		name:        name,
		description: opts.Description,
		codec:       codec,
		cacheDir:    opts.CacheDir,
		saver:       opts.Saver,
		loadConfig:  opts.LoadConfig,
		stamp:       opts.Stamp,
		onChange:    opts.OnChange,
		providers:   map[string]*provider[V]{},
	}
	Register(m)
	return m
}

// Name returns the data set's identifier.
func (m *Manager[V, R]) Name() string { return m.name }

// Description returns the human-readable purpose.
func (m *Manager[V, R]) Description() string { return m.description }

// SetEmbedded attaches the compiled-in default as the immutable "builtin"
// provider (lowest priority, never removed).
func (m *Manager[V, R]) SetEmbedded(parts ...V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hasBuiltin = true
	p := m.providers["builtin"]
	if p == nil {
		p = &provider[V]{
			cfg:     ProviderConfig{Name: "builtin", Kind: KindEmbedded, Enabled: true},
			builtin: true,
		}
		m.providers["builtin"] = p
	}
	p.parts = parts
	p.status, p.errMsg = "ok", ""
	if len(parts) > 0 {
		st := m.statsOf(parts)
		p.source, p.exported = st.Source, st.Exported
	}
	p.loadedAt = time.Now()
	m.reorderLocked()
	m.rebuildLocked()
}

// Current returns the published runtime value (zero value before the first
// build). The value is immutable: never mutate what Current returns.
func (m *Manager[V, R]) Current() R {
	p := m.built.Load()
	if p == nil {
		var zero R
		return zero
	}
	return *p
}

// Init loads persisted providers and starts the background refresh loop.
func (m *Manager[V, R]) Init() {
	m.loadFromConfig()
	// Refresh every interval-driven provider once at startup (cached data is
	// already in effect, so this only catches changes made while we were down).
	go m.SyncAll(false)
	go m.syncLoop()
}

// ---------------------------------------------------------------------------
// Loading

// loadFromConfig applies persisted config, then any extra/env config.
func (m *Manager[V, R]) loadFromConfig() {
	if m.loadConfig == nil {
		return
	}
	persisted, extra := m.loadConfig()
	var cfgs []ProviderConfig
	for _, raw := range []string{persisted, extra} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var part []ProviderConfig
		if err := json.Unmarshal([]byte(raw), &part); err != nil {
			log.Printf("datasets/%s: bad provider config: %v", m.name, err)
			continue
		}
		cfgs = append(cfgs, part...)
	}
	m.mu.Lock()
	for _, cfg := range cfgs {
		if cfg.Name == "" || cfg.Name == "builtin" {
			continue
		}
		p := &provider[V]{cfg: cfg}
		m.loadLocked(p) // later config for the same name wins
		if cfg.Kind == KindFile {
			p.mtime = mtimeOf(cfg.Path)
		}
		m.providers[cfg.Name] = p
	}
	m.reorderLocked()
	m.rebuildLocked()
	m.mu.Unlock()
}

// loadLocked loads a provider from local state only: the file/dir for
// kind=file, the on-disk cache for refreshable kinds. No network or process
// I/O happens here, so startup is fast and deterministic.
func (m *Manager[V, R]) loadLocked(p *provider[V]) {
	switch p.cfg.Kind {
	case KindFile:
		vals, err := m.readFileParts(p.cfg)
		if err != nil {
			p.parts = nil
			p.status, p.errMsg = "error", err.Error()
			return
		}
		m.acceptLocked(p, vals)
	case KindRemote, KindCommand:
		if data, err := os.ReadFile(m.cachePath(p.cfg.Name)); err == nil {
			if v, err := m.codec.Decode(data, p.cfg.Format); err == nil {
				m.acceptLocked(p, []V{v})
				if p.cfg.Kind == KindRemote {
					if tag, err := os.ReadFile(m.etagPath(p.cfg.Name)); err == nil {
						p.etag = strings.TrimSpace(string(tag))
					}
				}
			}
		}
	}
}

// acceptLocked installs decoded parts on a provider and records stats.
func (m *Manager[V, R]) acceptLocked(p *provider[V], vals []V) {
	if len(vals) == 0 {
		p.parts = nil
		p.status, p.errMsg = "error", "no data decoded"
		return
	}
	if m.stamp != nil {
		for i := range vals {
			vals[i] = m.stamp(vals[i], p.cfg.Name)
		}
	}
	p.parts = vals
	p.status, p.errMsg = "ok", ""
	p.loadedAt = time.Now()
	st := m.statsOf(vals)
	p.source, p.exported = st.Source, st.Exported
}

// readFileParts loads one file, or every decodable file in a directory.
func (m *Manager[V, R]) readFileParts(cfg ProviderConfig) ([]V, error) {
	if cfg.Path == "" {
		return nil, errors.New("no path given")
	}
	fi, err := os.Stat(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", cfg.Path, err)
	}
	if !fi.IsDir() {
		data, err := os.ReadFile(cfg.Path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", cfg.Path, err)
		}
		v, err := m.codec.Decode(data, cfg.Format)
		if err != nil {
			return nil, err
		}
		return []V{v}, nil
	}
	entries, err := os.ReadDir(cfg.Path)
	if err != nil {
		return nil, err
	}
	var vals []V
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(cfg.Path, e.Name()))
		if err != nil {
			return nil, err
		}
		v, err := m.codec.Decode(data, cfg.Format)
		if err != nil {
			// A folder may hold unrelated files; skip the ones we cannot decode.
			log.Printf("datasets/%s: skipping %s: %v", m.name, e.Name(), err)
			continue
		}
		vals = append(vals, v)
	}
	if len(vals) == 0 {
		return nil, fmt.Errorf("directory %s contains no decodable files", cfg.Path)
	}
	return vals, nil
}

// statsOf aggregates stats over parts.
func (m *Manager[V, R]) statsOf(parts []V) Stats {
	var st Stats
	for _, v := range parts {
		s := m.codec.Stats(v)
		st.Entries += s.Entries
		st.Observations += s.Observations
		if st.Source == "" {
			st.Source = s.Source
		}
		if st.Exported == "" {
			st.Exported = s.Exported
		}
	}
	return st
}

// ---------------------------------------------------------------------------
// Ordering & publish

// reorderLocked sorts provider names by priority desc, forcing "builtin" last.
func (m *Manager[V, R]) reorderLocked() {
	names := make([]string, 0, len(m.providers))
	for name := range m.providers {
		if name != "builtin" {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := m.providers[names[i]], m.providers[names[j]]
		if a.cfg.Priority != b.cfg.Priority {
			return a.cfg.Priority > b.cfg.Priority
		}
		return names[i] < names[j]
	})
	if _, ok := m.providers["builtin"]; ok {
		names = append(names, "builtin")
	}
	m.order = names
}

// rebuildLocked publishes a fresh immutable runtime value.
func (m *Manager[V, R]) rebuildLocked() {
	var parts []V
	for _, name := range m.order {
		p := m.providers[name]
		if !p.cfg.Enabled || len(p.parts) == 0 {
			continue
		}
		parts = append(parts, p.parts...)
	}
	if len(parts) == 0 {
		return
	}
	v := m.codec.Merge(parts)
	m.built.Store(&v)
	if m.onChange != nil {
		m.onChange(v)
	}
}

// ---------------------------------------------------------------------------
// Dataset (type-erased admin surface)

// Dataset is the type-erased view the admin API holds.
type Dataset interface {
	Name() string
	Description() string
	ListStatuses() []ProviderStatus
	Upsert(ProviderConfig) (ProviderStatus, error)
	Delete(providerName string) error
	Sync(providerName string) error
	SyncAll(force bool)
	Save() error
}

// ListStatuses returns all providers in priority order with live status.
func (m *Manager[V, R]) ListStatuses() []ProviderStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ProviderStatus, 0, len(m.order))
	for _, name := range m.order {
		out = append(out, m.statusLocked(m.providers[name]))
	}
	return out
}

func (m *Manager[V, R]) statusLocked(p *provider[V]) ProviderStatus {
	s := ProviderStatus{ProviderConfig: p.cfg, Builtin: p.builtin, Status: p.status, Error: p.errMsg,
		Source: p.source, Exported: p.exported}
	// Request headers (and userinfo embedded in the URL) may carry credentials:
	// report their presence, never the value, so a status/list call cannot leak
	// a token.
	s.Headers = maskHeaderValues(p.cfg.Headers)
	if u, err := url.Parse(p.cfg.URL); err == nil && u.User != nil {
		// Keep the literal mask readable: url.String() would percent-encode it.
		u.User = nil
		raw := u.String()
		if i := strings.Index(raw, "://"); i >= 0 {
			raw = raw[:i+3] + MaskedHeader + "@" + raw[i+3:]
		}
		s.URL = raw
	}
	if s.Status == "" {
		s.Status = "empty"
	}
	if !p.cfg.Enabled {
		s.Status = "disabled"
	}
	if len(p.parts) > 0 {
		st := m.statsOf(p.parts)
		s.Entries, s.Observations = st.Entries, st.Observations
	}
	if !p.lastSync.IsZero() {
		s.LastSync = p.lastSync.UTC().Format(time.RFC3339)
	}
	if !p.loadedAt.IsZero() {
		s.LoadedAt = p.loadedAt.UTC().Format(time.RFC3339)
	}
	return s
}

// Upsert creates or updates a provider, loads it and (for refreshable kinds)
// attempts an immediate refresh. A file provider that cannot be loaded is
// rejected so a bad configuration does not silently half-exist.
func (m *Manager[V, R]) Upsert(cfg ProviderConfig) (ProviderStatus, error) {
	if cfg.Name == "" {
		return ProviderStatus{}, errors.New("name is required")
	}
	if cfg.Name == "builtin" || cfg.Kind == KindEmbedded {
		return ProviderStatus{}, errors.New("the builtin provider cannot be modified")
	}
	switch cfg.Kind {
	case KindFile:
		if cfg.Path == "" {
			return ProviderStatus{}, errors.New("a file provider needs a path")
		}
	case KindRemote:
		if cfg.URL == "" {
			return ProviderStatus{}, errors.New("a remote provider needs a url")
		}
	case KindCommand:
		if cfg.Command == "" {
			return ProviderStatus{}, errors.New("a command provider needs a command")
		}
	default:
		return ProviderStatus{}, fmt.Errorf("kind must be %q, %q or %q", KindFile, KindRemote, KindCommand)
	}

	m.mu.Lock()
	p := m.providers[cfg.Name]
	existed := p != nil
	if p == nil {
		p = &provider[V]{}
		m.providers[cfg.Name] = p
	}
	prev := *p // rollback state if a file provider fails to load
	// URL userinfo is reported masked too; a masked value sent back means
	// "keep the stored credentials" for the same host/path.
	if p.cfg.URL != "" && strings.Contains(cfg.URL, "://"+MaskedHeader+"@") {
		if oldURL, err1 := url.Parse(p.cfg.URL); err1 == nil && oldURL.User != nil {
			if newURL, err2 := url.Parse(cfg.URL); err2 == nil {
				newURL.User = oldURL.User
				cfg.URL = newURL.String()
			}
		}
	}
	// A masked header value means "keep what is stored": status reports mask
	// credentials, so a client that edits a provider without retyping a token
	// must not overwrite it with the mask.
	if len(cfg.Headers) > 0 {
		merged := make(map[string]string, len(cfg.Headers))
		for k, v := range cfg.Headers {
			if v != MaskedHeader {
				merged[k] = v
				continue
			}
			if old, ok := p.cfg.Headers[k]; ok && old != MaskedHeader {
				merged[k] = old
			}
		}
		cfg.Headers = merged
	}
	kindChanged := p.cfg.Kind != "" && p.cfg.Kind != cfg.Kind
	if kindChanged || p.cfg.URL != cfg.URL {
		p.etag = "" // a different source must not be revalidated with the old validator
	}
	p.cfg = cfg
	// A new configuration invalidates any in-flight refresh: bump gen so its
	// result is discarded, and release the syncing flag so the immediate
	// refresh below can start right away.
	p.gen++
	p.syncing = false
	p.syncSeq++
	// Refreshable kinds keep their last good parts until a successful sync
	// replaces them: a failed fetch/command (or a restart from cache) must not
	// drop working data. File data is reloaded synchronously below, so stale
	// parts are cleared first; switching source kind also starts fresh.
	switch cfg.Kind {
	case KindRemote, KindCommand:
		if kindChanged {
			p.parts = nil
		}
	default:
		p.parts = nil
	}
	p.status, p.errMsg = "", ""
	m.loadLocked(p)
	if cfg.Kind == KindFile {
		if p.status == "error" {
			msg := p.errMsg
			if existed {
				*p = prev // keep the working configuration
			} else {
				delete(m.providers, cfg.Name) // never half-install a new provider
			}
			m.rebuildLocked()
			m.mu.Unlock()
			return ProviderStatus{}, errors.New("cannot load data: " + msg)
		}
		p.mtime = mtimeOf(cfg.Path)
	}
	m.reorderLocked()
	m.rebuildLocked()
	st := m.statusLocked(p)
	refresh := cfg.Enabled && (cfg.Kind == KindRemote || cfg.Kind == KindCommand)
	m.mu.Unlock()

	if refresh {
		// Network/process I/O happens outside the lock so other admin calls
		// and status reads are never blocked by a slow provider.
		m.refresh(cfg.Name)
		m.mu.Lock()
		if p = m.providers[cfg.Name]; p != nil {
			st = m.statusLocked(p)
		}
		m.mu.Unlock()
	}
	if err := m.persist(); err != nil {
		log.Printf("datasets/%s: persist failed: %v", m.name, err)
	}
	return st, nil
}

// Delete removes a custom provider.
func (m *Manager[V, R]) Delete(providerName string) error {
	if providerName == "" {
		return errors.New("name is required")
	}
	if providerName == "builtin" {
		return errors.New("the builtin provider cannot be deleted")
	}
	m.mu.Lock()
	if _, ok := m.providers[providerName]; !ok {
		m.mu.Unlock()
		return errors.New("no such provider")
	}
	delete(m.providers, providerName)
	os.Remove(m.cachePath(providerName))
	os.Remove(m.etagPath(providerName))
	m.reorderLocked()
	m.rebuildLocked()
	m.mu.Unlock()
	return m.persist()
}

// Sync refreshes a single provider by name. For a file provider this re-reads
// the file/directory unconditionally, which is the manual "reload" action.
func (m *Manager[V, R]) Sync(providerName string) error {
	m.mu.Lock()
	p, ok := m.providers[providerName]
	var kind Kind
	if ok {
		kind = p.cfg.Kind
	}
	m.mu.Unlock()
	if !ok {
		return errors.New("no such provider")
	}
	switch kind {
	case KindFile:
		m.reloadFile(providerName, true)
	case KindRemote, KindCommand:
		m.refresh(providerName)
	default:
		return errors.New("this provider has no refreshable source")
	}
	return nil
}

// SyncAll refreshes every due provider (or all enabled refreshable ones when
// force is true). Fetches run one at a time outside the manager lock.
func (m *Manager[V, R]) SyncAll(force bool) {
	type job struct {
		name string
		file bool
	}
	m.mu.Lock()
	var jobs []job
	for _, name := range m.order {
		p := m.providers[name]
		if !p.cfg.Enabled {
			continue
		}
		switch p.cfg.Kind {
		case KindFile:
			if force { // an explicit reload; scheduled watches live in syncDue
				jobs = append(jobs, job{name: name, file: true})
			}
		case KindRemote, KindCommand:
			// Interval 0 means "manual only": never refreshed by a schedule.
			if !force && (p.cfg.RefreshMin <= 0 ||
				time.Since(p.lastSync) < time.Duration(p.cfg.RefreshMin)*time.Minute) {
				continue
			}
			jobs = append(jobs, job{name: name})
		}
	}
	m.mu.Unlock()
	for _, j := range jobs {
		if j.file {
			m.reloadFile(j.name, true)
			continue
		}
		m.refresh(j.name)
	}
}

// syncAllAsync runs a full forced sync off the caller's goroutine.
func (m *Manager[V, R]) syncAllAsync() { go m.SyncAll(true) }

func (m *Manager[V, R]) syncLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		m.syncDue()
	}
}

// syncDue reloads every watched file provider whose content changed and
// refreshes at most one due remote/command provider per tick. All checks run
// under the lock; all I/O happens outside it.
func (m *Manager[V, R]) syncDue() {
	var refreshName string
	var watch []string
	m.mu.Lock()
	for _, name := range m.order {
		p := m.providers[name]
		if !p.cfg.Enabled || p.cfg.RefreshMin <= 0 {
			continue
		}
		if p.cfg.Kind == KindFile {
			if time.Since(p.lastCheck) >= time.Duration(p.cfg.RefreshMin)*time.Minute {
				watch = append(watch, name)
			}
			continue
		}
		if p.cfg.Kind != KindRemote && p.cfg.Kind != KindCommand {
			continue
		}
		if refreshName == "" &&
			time.Since(p.lastSync) >= time.Duration(p.cfg.RefreshMin)*time.Minute {
			refreshName = name
		}
	}
	m.mu.Unlock()

	for _, name := range watch {
		m.reloadFile(name, false)
	}
	if refreshName != "" {
		m.refresh(refreshName)
	}
}

// refresh fetches one remote/command provider outside the lock, then applies
// the result under it. A result whose generation was superseded (the provider
// was reconfigured or deleted meanwhile) is dropped.
func (m *Manager[V, R]) refresh(name string) {
	m.mu.Lock()
	p := m.providers[name]
	if p == nil || !p.cfg.Enabled || p.syncing ||
		(p.cfg.Kind != KindRemote && p.cfg.Kind != KindCommand) {
		m.mu.Unlock()
		return
	}
	p.syncing = true
	p.syncSeq++
	seq, gen := p.syncSeq, p.gen
	cfg, etag := p.cfg, p.etag
	m.mu.Unlock()

	data, newETag, notModified, err := m.fetchData(cfg, etag)

	// Decode outside the lock: building a large index (tens of thousands of
	// fingerprints) must not stall status/admin calls.
	var v V
	var decErr error
	if err == nil && !notModified {
		v, decErr = m.codec.Decode(data, cfg.Format)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	p = m.providers[name]
	if p == nil {
		return
	}
	if p.syncSeq == seq {
		p.syncing = false
	}
	if p.gen != gen {
		return // reconfigured while fetching; its own refresh will run
	}
	if err != nil {
		p.status = "error"
		if cfg.Kind == KindCommand {
			p.errMsg = "command failed: " + err.Error()
		} else {
			p.errMsg = "sync failed: " + err.Error()
		}
		return
	}
	if notModified {
		p.status, p.errMsg = "ok", ""
		p.lastSync = time.Now()
		return
	}
	if decErr != nil {
		p.status, p.errMsg = "error", "bad data: "+decErr.Error()
		return
	}
	p.etag = newETag
	m.writeETag(name, newETag)
	if err := m.writeCache(name, data); err != nil {
		log.Printf("datasets/%s: cache write for %s failed: %v", m.name, name, err)
	}
	m.acceptLocked(p, []V{v})
	p.lastSync = time.Now()
	m.rebuildLocked()
}

// fetchData obtains a refreshable provider's payload. It performs network or
// process I/O and must be called without the manager lock held.
func (m *Manager[V, R]) fetchData(cfg ProviderConfig, etag string) (data []byte, newETag string, notModified bool, err error) {
	switch cfg.Kind {
	case KindRemote:
		if isHTTPURL(cfg.URL) {
			res, err := httpFetchWithHeaders(cfg.URL, etag, cfg.Headers)
			return res.Data, res.ETag, res.NotModified, err
		}
		f := fetcherFor(cfg.URL)
		if f == nil {
			return nil, "", false, errors.New("unsupported URL scheme")
		}
		res, err := f(cfg.URL, etag)
		return res.Data, res.ETag, res.NotModified, err
	case KindCommand:
		out, err := runCommand(cfg.Command)
		return out, "", false, err
	}
	return nil, "", false, errors.New("provider kind is not refreshable")
}

// reloadFile re-reads a watched file/directory provider. A scheduled watch
// (force=false) only reloads when the newest modification time changed; a
// manual reload (force=true) always re-reads. Stat/read I/O runs outside the
// lock; the reload itself is atomic.
func (m *Manager[V, R]) reloadFile(name string, force bool) {
	m.mu.Lock()
	p := m.providers[name]
	if p == nil || p.cfg.Kind != KindFile || !p.cfg.Enabled {
		m.mu.Unlock()
		return
	}
	cfg := p.cfg
	gen := p.gen
	m.mu.Unlock()

	mt := mtimeOf(cfg.Path)

	m.mu.Lock()
	defer m.mu.Unlock()
	p = m.providers[name]
	if p == nil || p.gen != gen || p.cfg.Path != cfg.Path {
		return
	}
	p.lastCheck = time.Now()
	if !force && mt.Equal(p.mtime) && p.status == "ok" {
		return
	}
	vals, err := m.readFileParts(cfg)
	if err != nil {
		p.status, p.errMsg = "error", err.Error()
		return
	}
	m.acceptLocked(p, vals)
	p.mtime = mt
	m.rebuildLocked()
}

// isHTTPURL reports whether a provider URL uses (or implies) HTTP(S), the only
// transport that accepts custom request headers.
func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "", "http", "https":
		return true
	}
	return false
}

// mtimeOf returns the newest modification time at path. For a directory it is
// the newest mtime of its non-hidden regular files: a directory's own mtime
// does not change when a file's contents change.
func mtimeOf(path string) time.Time {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	if !fi.IsDir() {
		return fi.ModTime()
	}
	var newest time.Time
	entries, err := os.ReadDir(path)
	if err != nil {
		return time.Time{}
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest
}

// runCommand executes a user-defined data source and returns its stdout.
func runCommand(command string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	var sb limitedBuffer
	sb.limit = maxFetchBytes
	cmd.Stdout = &sb
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%v: %s", err, msg)
		}
		return nil, err
	}
	return sb.buf, nil
}

// limitedBuffer keeps at most limit bytes of command output.
type limitedBuffer struct {
	buf   []byte
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := b.limit - len(b.buf); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		b.buf = append(b.buf, p...)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Cache & persistence

func (m *Manager[V, R]) cachePath(name string) string {
	dir := m.cacheDir
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "echo-server-datasets")
	}
	return filepath.Join(dir, m.name, safeName(name)+".data")
}

func (m *Manager[V, R]) writeCache(name string, data []byte) error {
	path := m.cachePath(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// etagPath stores the last HTTP validator next to the cached payload, so a
// restart revalidates with If-None-Match instead of re-downloading the data.
func (m *Manager[V, R]) etagPath(name string) string { return m.cachePath(name) + ".etag" }

func (m *Manager[V, R]) writeETag(name, etag string) {
	if etag == "" {
		os.Remove(m.etagPath(name))
		return
	}
	path := m.etagPath(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Printf("datasets/%s: etag write for %s failed: %v", m.name, name, err)
		return
	}
	if err := os.WriteFile(path, []byte(etag), 0o600); err != nil {
		log.Printf("datasets/%s: etag write for %s failed: %v", m.name, name, err)
	}
}

// Save persists all custom providers through the configured saver.
func (m *Manager[V, R]) Save() error { return m.persist() }

func (m *Manager[V, R]) persist() error {
	if m.saver == nil {
		return nil
	}
	m.mu.Lock()
	cfgs := make([]ProviderConfig, 0, len(m.providers))
	for _, p := range m.providers {
		if p.builtin {
			continue
		}
		cfgs = append(cfgs, p.cfg)
	}
	m.mu.Unlock()
	sort.Slice(cfgs, func(i, j int) bool { return cfgs[i].Name < cfgs[j].Name })
	return m.saver(cfgs)
}

// ---------------------------------------------------------------------------
// Registry: every dataset the process knows, for the admin API.

var (
	regMu    sync.RWMutex
	reg      = map[string]Dataset{}
	regOrder []string
)

// Register adds a dataset to the process-wide registry (New does this).
func Register(d Dataset) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, ok := reg[d.Name()]; !ok {
		regOrder = append(regOrder, d.Name())
		sort.Strings(regOrder)
	}
	reg[d.Name()] = d
}

// Get returns a registered dataset by name.
func Get(name string) (Dataset, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	d, ok := reg[name]
	return d, ok
}

// All returns every registered dataset, sorted by name.
func All() []Dataset {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Dataset, 0, len(regOrder))
	for _, n := range regOrder {
		out = append(out, reg[n])
	}
	return out
}

// ResetRegistryForTest clears the registry (tests only).
func ResetRegistryForTest() {
	regMu.Lock()
	defer regMu.Unlock()
	reg = map[string]Dataset{}
	regOrder = nil
}

// safeName makes a provider name safe to use as a file name.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "provider"
	}
	return b.String()
}
