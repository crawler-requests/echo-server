package iplookup

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// providerFunc adapts a function to the Provider interface.
type providerFunc func(ip string) (*Info, error)

func (f providerFunc) Lookup(ip string) (*Info, error) { return f(ip) }

func register(t *testing.T, m *Manager, name string, f providerFunc) {
	t.Helper()
	m.RegisterDriver(name, func(Config) (Provider, error) { return f, nil })
}

func TestChainFallbackAndStats(t *testing.T) {
	m := New(Options{})
	register(t, m, "down", func(string) (*Info, error) { return nil, errors.New("rate limited") })
	register(t, m, "up", func(string) (*Info, error) { return &Info{Country: "Testland", City: "Testville"}, nil })
	if err := m.SeedBuiltin(Config{Name: "a", Driver: "down", Priority: 20}); err != nil {
		t.Fatal(err)
	}
	if err := m.SeedBuiltin(Config{Name: "b", Driver: "up", Priority: 10}); err != nil {
		t.Fatal(err)
	}
	info, provider, err := m.Lookup("8.8.8.8")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if provider != "b" || info.Source != "b" || info.Country != "Testland" {
		t.Fatalf("provider=%q info=%+v", provider, info)
	}
	if info.IP != "8.8.8.8" {
		t.Fatalf("ip = %q", info.IP)
	}
	st := m.List()
	if len(st) != 2 || st[0].Name != "a" || st[1].Name != "b" {
		t.Fatalf("order = %+v", st)
	}
	if st[0].Failures != 1 || st[0].LastError == "" || st[0].Status != "error" {
		t.Fatalf("failing provider stats = %+v", st[0])
	}
	if st[1].Successes != 1 || st[1].Status != "ok" || st[1].LastSuccess == "" {
		t.Fatalf("working provider stats = %+v", st[1])
	}
}

func TestPriorityOrdering(t *testing.T) {
	m := New(Options{})
	register(t, m, "lo", func(string) (*Info, error) { return &Info{Country: "Low"}, nil })
	register(t, m, "hi", func(string) (*Info, error) { return &Info{Country: "High"}, nil })
	_ = m.SeedBuiltin(Config{Name: "lo", Driver: "lo", Priority: 1})
	_ = m.SeedBuiltin(Config{Name: "hi", Driver: "hi", Priority: 100})
	info, provider, _ := m.Lookup("1.1.1.1")
	if provider != "hi" || info.Country != "High" {
		t.Fatalf("provider=%q country=%q", provider, info.Country)
	}
}

func TestDisabledAndGate(t *testing.T) {
	m := New(Options{Gate: func(c Config) bool { return c.Name != "blocked" }})
	register(t, m, "blocked", func(string) (*Info, error) { return &Info{Country: "Blocked"}, nil })
	register(t, m, "ok", func(string) (*Info, error) { return &Info{Country: "Allowed"}, nil })
	_ = m.SeedBuiltin(Config{Name: "blocked", Driver: "blocked", Priority: 50})
	_ = m.SeedBuiltin(Config{Name: "ok", Driver: "ok", Priority: 1})
	info, provider, _ := m.Lookup("1.1.1.1")
	if provider != "ok" || info.Country != "Allowed" {
		t.Fatalf("gated provider was used: %q %+v", provider, info)
	}
	blocked := m.List()[0]
	if blocked.Status != "gated" || !blocked.Gated || blocked.Calls != 0 {
		t.Fatalf("blocked status = %+v", blocked)
	}

	// Disabling the only usable provider leaves nothing to try.
	if _, err := m.Upsert(Config{Name: "ok", Enabled: false, Priority: 1}); err != nil {
		t.Fatal(err)
	}
	if info, provider, err := m.Lookup("1.1.1.1"); info != nil || provider != "" || err != nil {
		t.Fatalf("expected no answer, got %+v %q %v", info, provider, err)
	}
}

func TestRankOverridesOrder(t *testing.T) {
	m := New(Options{Rank: func(c Config, prio int) int {
		if c.Name == "boosted" {
			return 1000
		}
		return prio
	}})
	register(t, m, "normal", func(string) (*Info, error) { return &Info{Country: "Normal"}, nil })
	register(t, m, "boosted", func(string) (*Info, error) { return &Info{Country: "Boosted"}, nil })
	_ = m.SeedBuiltin(Config{Name: "normal", Driver: "normal", Priority: 100})
	_ = m.SeedBuiltin(Config{Name: "boosted", Driver: "boosted", Priority: 1})
	info, provider, _ := m.Lookup("1.1.1.1")
	if provider != "boosted" || info.Country != "Boosted" {
		t.Fatalf("provider=%q info=%+v", provider, info)
	}
}

// TestHTTPProviderMapping drives the generic cloud-API provider: URL template,
// auth header, nested field mapping, string coordinates and booleans.
func TestHTTPProviderMapping(t *testing.T) {
	var sawAuth atomicValue
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth.set(r.Header.Get("Authorization"))
		if r.URL.Path != "/lookup/203.0.113.7" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"data":{"location":{"country_name":"Testland","code":"tl","city":"Testville","lat":"12.5","lon":"-7.25"},
		                 "asn":64500,"asn_name":"Test Cloud","isp":"Test ISP",
		                 "flags":{"hosting":true,"proxy":false}}}`)
	}))
	defer srv.Close()

	m := New(Options{UserAgent: "iplookup-test"})
	st, err := m.Upsert(Config{
		Name: "cloud", Kind: KindHTTP, Enabled: true, Priority: 100,
		URL:     srv.URL + "/lookup/{ip}",
		Headers: map[string]string{"Authorization": "Bearer tok"},
		Mapping: map[string]string{
			"country": "data.location.country_name", "country_code": "data.location.code",
			"city": "data.location.city", "latitude": "data.location.lat",
			"longitude": "data.location.lon", "asn": "data.asn",
			"asn_name": "data.asn_name", "isp": "data.isp",
			"is_hosting": "data.flags.hosting", "is_proxy": "data.flags.proxy",
		},
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if st.Headers["Authorization"] != MaskedSecret {
		t.Fatalf("status leaked header: %+v", st.Headers)
	}
	info, provider, err := m.Lookup("203.0.113.7")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if provider != "cloud" || sawAuth.get() != "Bearer tok" {
		t.Fatalf("provider=%q auth=%q", provider, sawAuth.get())
	}
	if info.Country != "Testland" || info.CountryCode != "TL" || info.City != "Testville" ||
		info.Latitude != 12.5 || info.Longitude != -7.25 {
		t.Fatalf("geo = %+v", info)
	}
	if info.ASN != "AS64500" || info.ASNName != "Test Cloud" || info.ISP != "Test ISP" {
		t.Fatalf("network fields = %+v", info)
	}
	if info.IsHosting == nil || !*info.IsHosting || info.IsProxy == nil || *info.IsProxy {
		t.Fatalf("privacy flags = %+v", info)
	}

	// Posting the mask back keeps the stored token.
	if _, err := m.Upsert(Config{
		Name: "cloud", Kind: KindHTTP, Enabled: true, Priority: 100,
		URL: srv.URL + "/lookup/{ip}", Headers: map[string]string{"Authorization": MaskedSecret},
		Mapping: map[string]string{"country": "data.location.country_name"},
	}); err != nil {
		t.Fatal(err)
	}
	sawAuth.set("")
	if _, _, err := m.Lookup("203.0.113.7"); err != nil {
		t.Fatalf("lookup after masked update: %v", err)
	}
	if got := sawAuth.get(); got != "Bearer tok" {
		t.Fatalf("masked update lost the token, server saw %q", got)
	}
}

func TestHTTPProviderNormalizedContract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip":"198.51.100.9","country":"Normland","asn":"AS64511","is_vpn":true}`)
	}))
	defer srv.Close()
	m := New(Options{})
	if _, err := m.Upsert(Config{Name: "contract", Kind: KindHTTP, Enabled: true, URL: srv.URL + "/?q={ip}"}); err != nil {
		t.Fatal(err)
	}
	info, _, err := m.Lookup("198.51.100.9")
	if err != nil {
		t.Fatal(err)
	}
	if info.Country != "Normland" || info.ASN != "AS64511" || info.IsVPN == nil || !*info.IsVPN {
		t.Fatalf("info = %+v", info)
	}
}

func TestCommandProvider(t *testing.T) {
	m := New(Options{})
	if _, err := m.Upsert(Config{
		Name: "local-script", Kind: KindCommand, Enabled: true, Priority: 100,
		Command: `printf '{"ip":"%s","country":"Cmdland","city":"Shellville","is_tor":true}' {ip}`,
	}); err != nil {
		t.Fatal(err)
	}
	info, provider, err := m.Lookup("203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if provider != "local-script" || info.Country != "Cmdland" || info.City != "Shellville" ||
		info.IsTor == nil || !*info.IsTor {
		t.Fatalf("provider=%q info=%+v", provider, info)
	}
}

func TestCommandFailureFallsThrough(t *testing.T) {
	m := New(Options{})
	register(t, m, "ok", func(string) (*Info, error) { return &Info{Country: "Second"}, nil })
	if _, err := m.Upsert(Config{
		Name: "broken", Kind: KindCommand, Enabled: true, Priority: 50,
		Command: `echo "boom" >&2; exit 3 # {ip}`,
	}); err != nil {
		t.Fatal(err)
	}
	_ = m.SeedBuiltin(Config{Name: "fallback", Driver: "ok", Priority: 1})
	info, provider, err := m.Lookup("1.1.1.1")
	if err != nil || provider != "fallback" || info.Country != "Second" {
		t.Fatalf("provider=%q info=%+v err=%v", provider, info, err)
	}
	first := m.List()[0]
	if first.Name != "broken" || first.Failures != 1 || !strings.Contains(first.LastError, "boom") {
		t.Fatalf("broken stats = %+v", first)
	}
}

func TestUpsertValidation(t *testing.T) {
	m := New(Options{})
	register(t, m, "drv", func(string) (*Info, error) { return &Info{Country: "X"}, nil })
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no name", Config{Kind: KindHTTP, URL: "http://x/{ip}"}},
		{"http without placeholder", Config{Name: "h", Kind: KindHTTP, URL: "http://x/"}},
		{"http without url", Config{Name: "h", Kind: KindHTTP}},
		{"command without placeholder", Config{Name: "c", Kind: KindCommand, Command: "echo hi"}},
		{"command without command", Config{Name: "c", Kind: KindCommand}},
		{"builtin unknown driver", Config{Name: "b", Kind: KindBuiltin, Driver: "nope"}},
		{"unknown kind", Config{Name: "x", Kind: "smtp"}},
	}
	for _, c := range cases {
		if _, err := m.Upsert(c.cfg); err == nil {
			t.Fatalf("%s: expected an error", c.name)
		}
	}
	if err := m.SeedBuiltin(Config{Name: "drv", Driver: "drv"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Upsert(Config{Name: "drv", Kind: KindHTTP, URL: "http://x/{ip}"}); err == nil {
		t.Fatal("builtin kind change must be rejected")
	}
	if _, err := m.Upsert(Config{Name: "drv", Driver: "other"}); err == nil {
		t.Fatal("builtin driver change must be rejected")
	}
	if err := m.Delete("drv"); err == nil {
		t.Fatal("builtin delete must be rejected")
	}
	if _, err := m.Upsert(Config{Name: "custom", Kind: KindHTTP, Enabled: true, URL: "http://x/{ip}"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete("custom"); err != nil {
		t.Fatal(err)
	}
}

func TestPersistence(t *testing.T) {
	var saved []Config
	m1 := New(Options{Saver: func(c []Config) error { saved = c; return nil }})
	register(t, m1, "drv", func(string) (*Info, error) { return &Info{Country: "Built"}, nil })
	_ = m1.SeedBuiltin(Config{Name: "drv", Driver: "drv", Priority: 10})
	if _, err := m1.Upsert(Config{Name: "cloud", Kind: KindHTTP, Enabled: true, Priority: 70, URL: "http://cloud.example/{ip}"}); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 2 {
		t.Fatalf("saved %d providers, want 2", len(saved))
	}
	raw, _ := json.Marshal(saved)

	m2 := New(Options{LoadConfig: func() (string, string) { return string(raw), "" }})
	register(t, m2, "drv", func(string) (*Info, error) { return &Info{Country: "Built"}, nil })
	_ = m2.SeedBuiltin(Config{Name: "drv", Driver: "drv", Priority: 10})
	m2.Init()
	var found bool
	for _, st := range m2.List() {
		if st.Name == "cloud" {
			found = true
			if st.URL != "http://cloud.example/{ip}" || st.Priority != 70 {
				t.Fatalf("restored config = %+v", st)
			}
		}
	}
	if !found {
		t.Fatal("custom provider was not restored")
	}
}

func TestInitSkipsBadConfig(t *testing.T) {
	m := New(Options{LoadConfig: func() (string, string) { return "not json", `[{"name":"x","kind":"http","enabled":true}]` }})
	m.Init() // must not panic; the bad entry needs a URL and is skipped
	if got := m.List(); len(got) != 0 {
		t.Fatalf("providers = %+v", got)
	}
}

func TestMaskInherit(t *testing.T) {
	old := map[string]string{"Authorization": "Bearer real", "X-Key": "k"}
	got := maskInherit(map[string]string{"Authorization": MaskedSecret, "X-Key": "new"}, old)
	if got["Authorization"] != "Bearer real" || got["X-Key"] != "new" {
		t.Fatalf("maskInherit = %+v", got)
	}
	if got := maskInherit(map[string]string{"Authorization": MaskedSecret}, nil); len(got) != 0 {
		t.Fatalf("mask without a stored value should drop the header, got %+v", got)
	}
}

// atomicValue is a tiny race-free string holder for test handlers.
type atomicValue struct {
	mu sync.Mutex
	v  string
}

func (a *atomicValue) set(v string) { a.mu.Lock(); a.v = v; a.mu.Unlock() }
func (a *atomicValue) get() string  { a.mu.Lock(); defer a.mu.Unlock(); return a.v }
