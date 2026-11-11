// Package iplookup is a pluggable IP-intelligence lookup engine: a chain of
// providers, tried in priority order, that turns an IP address into normalized
// ASN / geolocation / privacy fields.
//
// It complements the bulk data engine in package datasets. That engine merges
// static data sets (CIDR tables, fingerprint libraries); this one models *query*
// sources, where each provider is asked about one IP and may answer or fail.
//
// Three provider kinds ship here:
//
//	kind      source                                     answered by
//	builtin   a driver registered by the embedder        Go code (e.g. ipwho.is)
//	http      a cloud API URL template with {ip}         JSON + a field mapping
//	command   stdout of a shell command with {ip}        JSON + a field mapping
//
// The chain is the point: several cloud APIs can be combined, and the first
// provider that returns usable data wins. Failures are recorded per provider
// (calls/successes/failures/last error/latency) and never abort the chain, so a
// rate-limited free API simply hands over to the next provider.
//
// A JSON document in the normalized shape (see Info) is accepted as-is; any
// other API response can be described with a Mapping of Info field → dot path
// (e.g. {"country": "location.country", "latitude": "location.lat"}), so a new
// cloud API needs no Go code.
package iplookup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kind is how a provider produces an answer.
type Kind string

const (
	KindBuiltin Kind = "builtin" // driver registered with RegisterDriver (Go code)
	KindHTTP    Kind = "http"    // cloud API URL template containing {ip}
	KindCommand Kind = "command" // shell command containing {ip}, JSON on stdout
)

// MaskedSecret replaces credential values in every status response.
const MaskedSecret = "***"

// Info is the normalized answer of one provider.
type Info struct {
	IP          string  `json:"ip,omitempty"`
	Continent   string  `json:"continent,omitempty"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Postal      string  `json:"postal,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	UTCOffset   string  `json:"utc_offset,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	ASN         string  `json:"asn,omitempty"`
	ASNName     string  `json:"asn_name,omitempty"`
	Org         string  `json:"org,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	IsProxy     *bool   `json:"is_proxy,omitempty"`
	IsVPN       *bool   `json:"is_vpn,omitempty"`
	IsTor       *bool   `json:"is_tor,omitempty"`
	IsHosting   *bool   `json:"is_hosting,omitempty"`
	Source      string  `json:"source,omitempty"` // provider name that supplied this answer
}

// Usable reports whether the answer carries any information worth using. A
// provider may legitimately answer with only ASN or only privacy flags.
func (i *Info) Usable() bool {
	if i == nil {
		return false
	}
	return i.Country != "" || i.CountryCode != "" || i.Region != "" || i.City != "" ||
		i.Postal != "" || i.Timezone != "" || i.Latitude != 0 || i.Longitude != 0 ||
		i.ASN != "" || i.ASNName != "" || i.Org != "" || i.ISP != "" ||
		i.IsProxy != nil || i.IsVPN != nil || i.IsTor != nil || i.IsHosting != nil
}

// Provider answers one IP. A provider should return an error when the source
// is unreachable or rejects the query, and (nil, nil) when it has no data.
type Provider interface {
	Lookup(ip string) (*Info, error)
}

// Factory builds a Provider from its configuration. Registered drivers receive
// the full config, so a driver may read Params.
type Factory func(Config) (Provider, error)

// Config is the persisted, user-editable description of one provider.
type Config struct {
	Name     string            `json:"name"`
	Kind     Kind              `json:"kind"`
	Driver   string            `json:"driver,omitempty"`      // builtin kind: registered driver name
	Enabled  bool              `json:"enabled"`               // participate in the chain
	Priority int               `json:"priority"`              // higher is tried first
	URL      string            `json:"url,omitempty"`         // http kind: template with {ip} / {ip_raw}
	Headers  map[string]string `json:"headers,omitempty"`     // http kind: request headers (auth tokens)
	Mapping  map[string]string `json:"mapping,omitempty"`     // http/command: Info field -> dot path in JSON
	Command  string            `json:"command,omitempty"`     // command kind: shell command with {ip}
	Params   map[string]string `json:"params,omitempty"`      // builtin kind: driver-specific options
	TimeoutS int               `json:"timeout_sec,omitempty"` // per-lookup timeout, default 4
}

// Status is the API view of a provider: config (credentials masked) plus live
// statistics.
type Status struct {
	Config
	Builtin     bool    `json:"builtin"`
	Status      string  `json:"status"` // ok | error | empty | disabled | gated
	Gated       bool    `json:"gated,omitempty"`
	LastError   string  `json:"last_error,omitempty"`
	Calls       uint64  `json:"calls"`
	Successes   uint64  `json:"successes"`
	Failures    uint64  `json:"failures"`
	AvgMillis   float64 `json:"avg_ms"`
	LastSuccess string  `json:"last_success,omitempty"`
}

// Options configures a Manager.
type Options struct {
	// Saver persists the full provider list after a change. Optional.
	Saver func([]Config) error
	// LoadConfig returns the persisted config JSON and an optional extra JSON
	// (e.g. from the environment) applied after it. Optional.
	LoadConfig func() (persisted, extra string)
	// Gate decides, at lookup time, whether a provider participates. It lets the
	// host apply global switches (e.g. "online lookups off") without rewriting
	// the stored configuration. Optional.
	Gate func(Config) bool
	// Rank overrides a provider's effective priority at lookup time (e.g. boost
	// an API once an auth token is configured). Optional.
	Rank func(Config, int) int
	// HTTPClient is used by http providers. Default: 4s timeout.
	HTTPClient *http.Client
	// UserAgent is sent by http providers when the provider did not set one.
	UserAgent string
}

// Manager owns one lookup chain.
type Manager struct {
	opts    Options
	drivers map[string]Factory

	mu      sync.RWMutex
	entries map[string]*entry
	order   []string // priority desc, then name
}

// entry is the live provider plus its statistics.
type entry struct {
	cfg     Config
	builtin bool
	p       Provider

	mu          sync.Mutex
	lastErr     string
	lastSuccess time.Time
	calls       uint64
	successes   uint64
	failures    uint64
	totalMs     float64
}

func (e *entry) record(ms float64, err error, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	e.totalMs += ms
	if err != nil {
		e.failures++
		e.lastErr = err.Error()
		return
	}
	if ok {
		e.successes++
		e.lastErr = ""
		e.lastSuccess = time.Now()
		return
	}
	e.failures++
	e.lastErr = "provider returned no usable data"
}

func (e *entry) stats() (calls, successes, failures uint64, avg float64, lastErr string, lastSuccess time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.calls > 0 {
		avg = e.totalMs / float64(e.calls)
	}
	return e.calls, e.successes, e.failures, avg, e.lastErr, e.lastSuccess
}

func (e *entry) resetStats() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls, e.successes, e.failures, e.totalMs = 0, 0, 0, 0
	e.lastErr = ""
}

// New creates an empty manager.
func New(opts Options) *Manager {
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 4 * time.Second}
	}
	return &Manager{
		opts:    opts,
		drivers: map[string]Factory{},
		entries: map[string]*entry{},
	}
}

// RegisterDriver adds a builtin driver usable by kind=builtin providers.
func (m *Manager) RegisterDriver(name string, f Factory) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drivers[name] = f
}

// SeedBuiltin installs a builtin provider if nothing with that name exists yet
// (persisted configuration applied later in Init wins over the seed).
func (m *Manager) SeedBuiltin(cfg Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[cfg.Name]; ok {
		return nil
	}
	cfg.Kind = KindBuiltin
	cfg.Enabled = true
	p, err := m.buildLocked(cfg)
	if err != nil {
		return err
	}
	m.entries[cfg.Name] = &entry{cfg: cfg, builtin: true, p: p}
	m.reorderLocked()
	return nil
}

// Init loads the persisted provider list, then the optional extra list (env).
// Bad entries are logged and skipped; startup never fails because of one.
func (m *Manager) Init() {
	if m.opts.LoadConfig == nil {
		return
	}
	persisted, extra := m.opts.LoadConfig()
	for _, raw := range []string{persisted, extra} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var cfgs []Config
		if err := json.Unmarshal([]byte(raw), &cfgs); err != nil {
			log.Printf("iplookup: bad provider config: %v", err)
			continue
		}
		for _, cfg := range cfgs {
			if _, err := m.upsert(cfg, false); err != nil {
				log.Printf("iplookup: provider %q: %v", cfg.Name, err)
			}
		}
	}
}

// Upsert creates or updates a provider, persists the change and returns its
// live status. Builtins accept only Enabled/Priority (their driver and kind are
// fixed); a custom provider can be edited freely.
func (m *Manager) Upsert(cfg Config) (Status, error) {
	st, err := m.upsert(cfg, true)
	return st, err
}

func (m *Manager) upsert(cfg Config, save bool) (Status, error) {
	if cfg.Name == "" {
		return Status{}, errors.New("name is required")
	}
	cfg.Headers = maskInherit(cfg.Headers, m.existingHeaders(cfg.Name))

	m.mu.Lock()
	e := m.entries[cfg.Name]
	existed := e != nil
	if existed && e.builtin {
		if cfg.Kind != "" && cfg.Kind != KindBuiltin {
			m.mu.Unlock()
			return Status{}, errors.New("a builtin provider's kind cannot be changed")
		}
		if cfg.Driver != "" && cfg.Driver != e.cfg.Driver {
			m.mu.Unlock()
			return Status{}, errors.New("a builtin provider's driver cannot be changed")
		}
		merged := e.cfg
		merged.Enabled = cfg.Enabled
		merged.Priority = cfg.Priority
		if cfg.Params != nil {
			merged.Params = cfg.Params
		}
		cfg = merged
	} else if existed && cfg.Kind == "" {
		cfg.Kind = e.cfg.Kind
	}
	p, err := m.buildLocked(cfg)
	if err != nil {
		m.mu.Unlock()
		return Status{}, err
	}
	if !existed || !e.builtin {
		e = &entry{cfg: cfg}
		m.entries[cfg.Name] = e
	}
	e.cfg = cfg
	e.p = p
	e.resetStats()
	m.reorderLocked()
	st := m.statusLocked(e)
	m.mu.Unlock()

	if save {
		if err := m.persist(); err != nil {
			log.Printf("iplookup: persist failed: %v", err)
		}
	}
	return st, nil
}

// buildLocked validates a config and constructs its provider. Caller holds mu.
func (m *Manager) buildLocked(cfg Config) (Provider, error) {
	switch cfg.Kind {
	case KindBuiltin:
		if cfg.Driver == "" {
			return nil, errors.New("a builtin provider needs a driver")
		}
		f, ok := m.drivers[cfg.Driver]
		if !ok {
			return nil, fmt.Errorf("unknown driver %q", cfg.Driver)
		}
		p, err := f(cfg)
		if err != nil {
			return nil, err
		}
		if p == nil {
			return nil, errors.New("driver returned no provider")
		}
		return p, nil
	case KindHTTP:
		if cfg.URL == "" {
			return nil, errors.New("an http provider needs a url")
		}
		if !strings.Contains(cfg.URL, "{ip}") && !strings.Contains(cfg.URL, "{ip_raw}") {
			return nil, errors.New(`an http provider url must contain {ip} or {ip_raw}`)
		}
		if _, err := url.Parse(strings.ReplaceAll(cfg.URL, "{ip}", "1.2.3.4")); err != nil {
			return nil, fmt.Errorf("bad url: %w", err)
		}
		return &httpProvider{cfg: cfg, client: m.opts.HTTPClient, ua: m.opts.UserAgent, timeout: timeoutOf(cfg)}, nil
	case KindCommand:
		if cfg.Command == "" {
			return nil, errors.New("a command provider needs a command")
		}
		if !strings.Contains(cfg.Command, "{ip}") {
			return nil, errors.New("a command provider command must contain {ip}")
		}
		return &commandProvider{cfg: cfg, timeout: timeoutOf(cfg)}, nil
	}
	return nil, fmt.Errorf("kind must be %q, %q or %q", KindBuiltin, KindHTTP, KindCommand)
}

// Delete removes a custom provider. Builtins can be disabled but not deleted.
func (m *Manager) Delete(name string) error {
	if name == "" {
		return errors.New("name is required")
	}
	m.mu.Lock()
	e, ok := m.entries[name]
	if !ok {
		m.mu.Unlock()
		return errors.New("no such provider")
	}
	if e.builtin {
		m.mu.Unlock()
		return errors.New("a builtin provider cannot be deleted (disable it instead)")
	}
	delete(m.entries, name)
	m.reorderLocked()
	m.mu.Unlock()
	return m.persist()
}

// List returns every provider in chain order with its live statistics.
func (m *Manager) List() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Status, 0, len(m.order))
	for _, name := range m.order {
		out = append(out, m.statusLocked(m.entries[name]))
	}
	return out
}

func (m *Manager) statusLocked(e *entry) Status {
	calls, successes, failures, avg, lastErr, lastSuccess := e.stats()
	st := Status{
		Config:    e.cfg,
		Builtin:   e.builtin,
		Calls:     calls,
		Successes: successes,
		Failures:  failures,
		AvgMillis: round1(avg),
		LastError: lastErr,
	}
	st.Headers = maskHeaders(e.cfg.Headers)
	gated := m.opts.Gate != nil && !m.opts.Gate(e.cfg)
	st.Gated = gated
	switch {
	case !e.cfg.Enabled:
		st.Status = "disabled"
	case gated:
		st.Status = "gated"
	case lastErr != "":
		st.Status = "error"
	case successes > 0:
		st.Status = "ok"
	default:
		st.Status = "empty"
	}
	if !lastSuccess.IsZero() {
		st.LastSuccess = lastSuccess.UTC().Format(time.RFC3339)
	}
	return st
}

// Lookup walks the chain and returns the first usable answer. The second
// result is the provider name that answered. When every provider failed, the
// returned error describes the last failure (nil when nothing was attempted,
// e.g. everything disabled or gated).
func (m *Manager) Lookup(ip string) (*Info, string, error) {
	if m == nil || strings.TrimSpace(ip) == "" {
		return nil, "", nil
	}
	type cand struct {
		e   *entry
		cfg Config
	}
	m.mu.RLock()
	cands := make([]cand, 0, len(m.order))
	for _, name := range m.order {
		e := m.entries[name]
		cands = append(cands, cand{e: e, cfg: e.cfg})
	}
	gate, rank := m.opts.Gate, m.opts.Rank
	m.mu.RUnlock()

	if rank != nil {
		sort.SliceStable(cands, func(i, j int) bool {
			return rank(cands[i].cfg, cands[i].cfg.Priority) > rank(cands[j].cfg, cands[j].cfg.Priority)
		})
	}

	var lastErr error
	for _, c := range cands {
		if !c.cfg.Enabled {
			continue
		}
		if gate != nil && !gate(c.cfg) {
			continue
		}
		start := time.Now()
		info, err := c.e.p.Lookup(ip)
		ms := float64(time.Since(start).Microseconds()) / 1000
		usable := err == nil && info.Usable()
		c.e.record(ms, err, usable)
		if usable {
			if info.IP == "" {
				info.IP = ip
			}
			info.Source = c.cfg.Name
			return info, c.cfg.Name, nil
		}
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", c.cfg.Name, err)
		}
	}
	return nil, "", lastErr
}

// Save persists the current provider list.
func (m *Manager) Save() error { return m.persist() }

func (m *Manager) persist() error {
	if m.opts.Saver == nil {
		return nil
	}
	m.mu.RLock()
	cfgs := make([]Config, 0, len(m.order))
	for _, name := range m.order {
		cfgs = append(cfgs, m.entries[name].cfg)
	}
	m.mu.RUnlock()
	return m.opts.Saver(cfgs)
}

func (m *Manager) existingHeaders(name string) map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if e := m.entries[name]; e != nil {
		return e.cfg.Headers
	}
	return nil
}

func (m *Manager) reorderLocked() {
	m.order = m.order[:0]
	for name := range m.entries {
		m.order = append(m.order, name)
	}
	sort.Slice(m.order, func(i, j int) bool {
		a, b := m.entries[m.order[i]].cfg, m.entries[m.order[j]].cfg
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		return a.Name < b.Name
	})
}

// ---------------------------------------------------------------------------
// Providers

// httpProvider calls a cloud API described by a URL template and a field
// mapping.
type httpProvider struct {
	cfg     Config
	client  *http.Client
	ua      string
	timeout time.Duration
}

func (p *httpProvider) Lookup(ip string) (*Info, error) {
	target := strings.ReplaceAll(p.cfg.URL, "{ip_raw}", ip)
	target = strings.ReplaceAll(target, "{ip}", url.QueryEscape(ip))
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range p.cfg.Headers {
		req.Header.Set(k, v)
	}
	if p.ua != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", p.ua)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return decodeInfo(body, p.cfg.Mapping)
}

// commandProvider runs a shell command (stdout is JSON) described by the same
// field mapping.
type commandProvider struct {
	cfg     Config
	timeout time.Duration
}

func (p *commandProvider) Lookup(ip string) (*Info, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	cmdStr := strings.ReplaceAll(p.cfg.Command, "{ip}", shellQuote(ip))
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	var stdout, stderr capBuffer
	stdout.max, stderr.max = 1<<20, 4<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("command timed out after %s", p.timeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return nil, err
		}
		return nil, fmt.Errorf("%v: %s", err, msg)
	}
	return decodeInfo(stdout.Bytes(), p.cfg.Mapping)
}

// capBuffer accumulates writes up to max bytes and silently drops the rest.
type capBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *capBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *capBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *capBuffer) String() string { return b.buf.String() }

func timeoutOf(cfg Config) time.Duration {
	if cfg.TimeoutS <= 0 {
		return 4 * time.Second
	}
	if cfg.TimeoutS > 60 {
		return 60 * time.Second
	}
	return time.Duration(cfg.TimeoutS) * time.Second
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// decodeInfo turns a provider response into Info: either the normalized
// contract (same names as Info's JSON tags) or, with a Mapping, arbitrary JSON.
func decodeInfo(data []byte, mapping map[string]string) (*Info, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("response is not JSON: %w", err)
	}
	info := &Info{}
	if len(mapping) == 0 {
		raw, err := json.Marshal(root)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, info); err != nil {
			return nil, fmt.Errorf("response does not match the normalized contract: %w", err)
		}
	} else {
		for field, path := range mapping {
			v := lookupPath(root, path)
			if v != nil {
				setField(info, field, v)
			}
		}
	}
	if !info.Usable() {
		return nil, errors.New("response has no usable IP fields (add a mapping)")
	}
	return info, nil
}

// lookupPath resolves a dot path ("location.country", "items.0.city") in
// decoded JSON.
func lookupPath(root any, path string) any {
	cur := root
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			return nil
		}
		switch v := cur.(type) {
		case map[string]any:
			cur = v[part]
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(v) {
				return nil
			}
			cur = v[i]
		default:
			return nil
		}
	}
	return cur
}

// setField writes one mapped value into Info. Unknown fields are ignored, so a
// mapping may document extra API fields without breaking.
func setField(info *Info, field string, v any) {
	switch field {
	case "ip":
		info.IP = valueString(v)
	case "continent":
		info.Continent = valueString(v)
	case "country":
		info.Country = valueString(v)
	case "country_code":
		info.CountryCode = strings.ToUpper(valueString(v))
	case "region":
		info.Region = valueString(v)
	case "city":
		info.City = valueString(v)
	case "postal":
		info.Postal = valueString(v)
	case "timezone":
		info.Timezone = valueString(v)
	case "utc_offset":
		info.UTCOffset = valueString(v)
	case "latitude", "lat":
		info.Latitude = valueFloat(v)
	case "longitude", "lon", "lng":
		info.Longitude = valueFloat(v)
	case "asn":
		s := valueString(v)
		if s != "" && isDigits(s) {
			s = "AS" + s
		}
		info.ASN = s
	case "asn_name":
		info.ASNName = valueString(v)
	case "org":
		info.Org = valueString(v)
	case "isp":
		info.ISP = valueString(v)
	case "is_proxy":
		info.IsProxy = valueBool(v)
	case "is_vpn":
		info.IsVPN = valueBool(v)
	case "is_tor":
		info.IsTor = valueBool(v)
	case "is_hosting":
		info.IsHosting = valueBool(v)
	}
}

func valueString(v any) string {
	switch v := v.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func valueFloat(v any) float64 {
	switch v := v.(type) {
	case float64:
		return v
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f
	}
	return 0
}

func valueBool(v any) *bool {
	var b bool
	switch v := v.(type) {
	case bool:
		b = v
	case float64:
		b = v != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes", "y":
			b = true
		case "false", "0", "no", "n":
			b = false
		default:
			return nil
		}
	default:
		return nil
	}
	return &b
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// maskHeaders reports which headers exist without revealing secrets. A nil map
// stays nil so JSON omits the field.
func maskHeaders(h map[string]string) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k := range h {
		out[k] = MaskedSecret
	}
	return out
}

// maskInherit replaces masked values with the stored ones, so editing a
// provider without retyping a token does not overwrite it.
func maskInherit(newHeaders, old map[string]string) map[string]string {
	if len(newHeaders) == 0 {
		return nil
	}
	out := make(map[string]string, len(newHeaders))
	for k, v := range newHeaders {
		if v == MaskedSecret {
			if old != nil {
				if prev, ok := old[k]; ok && prev != MaskedSecret {
					out[k] = prev
					continue
				}
			}
			continue
		}
		out[k] = v
	}
	return out
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
