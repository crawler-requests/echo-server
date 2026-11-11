package main

import (
	"strings"
	"testing"
)

// The embedded JA4DB snapshot must load and be big enough to be useful; a
// truncated or corrupt data/ja4db.json would otherwise degrade silently to
// "everything is unknown".
func TestJA4DB_Loaded(t *testing.T) {
	if !ja4DB.ok {
		t.Fatal("embedded JA4DB failed to load")
	}
	if len(ja4DB.exact) < 1000 {
		t.Errorf("only %d fingerprints loaded, want the full snapshot (>1000)", len(ja4DB.exact))
	}
	if len(ja4DB.prefix) < 500 {
		t.Errorf("only %d JA4 prefixes loaded, want >500", len(ja4DB.prefix))
	}
	if ja4DB.meta.Exported == "" || ja4DB.meta.Source == "" {
		t.Errorf("database metadata missing: %+v", ja4DB.meta)
	}
}

// The most commonly observed Chrome fingerprint in JA4DB must resolve to
// Chrome with high confidence and a version range.
func TestLookupJA4_ExactChrome(t *testing.T) {
	m := lookupJA4("t13d1516h2_8daaf6152771_d8a2da3f94cd")
	if m == nil {
		t.Fatal("known Chrome JA4 did not match")
	}
	if !m.Exact {
		t.Errorf("expected an exact match, got prefix match")
	}
	if m.Name != "Chrome" || m.Family != "browser" {
		t.Errorf("got %s/%s, want Chrome/browser (candidates %v)", m.Name, m.Family, m.Candidates)
	}
	if m.Confidence < 0.9 {
		t.Errorf("confidence = %.2f, want >=0.9 for a dominant fingerprint", m.Confidence)
	}
	if m.Observations < 1000 {
		t.Errorf("observations = %d, want the real observation count", m.Observations)
	}
	if m.Version == "" {
		t.Errorf("expected an observed version, got none")
	}
}

// A client build newer than the snapshot gets a new extension hash, but the
// cipher list is unchanged — the prefix tier must still name it.
func TestLookupJA4_PrefixFallback(t *testing.T) {
	m := lookupJA4("t13d1516h2_8daaf6152771_ffffffffffff")
	if m == nil {
		t.Fatal("prefix tier did not match a Chrome-family fingerprint")
	}
	if m.Exact {
		t.Fatalf("expected a prefix match, got exact")
	}
	if m.Name != "Chrome" || m.Family != "browser" {
		t.Errorf("prefix match got %s/%s, want Chrome/browser", m.Name, m.Family)
	}
	if m.Confidence >= 0.95 {
		t.Errorf("prefix matches must be less confident than exact ones, got %.2f", m.Confidence)
	}
	if !strings.Contains(strings.Join([]string{m.Note}, " "), "prefix") {
		t.Errorf("prefix match should be explained in the note, got %q", m.Note)
	}
}

func TestLookupJA4_Unknown(t *testing.T) {
	if m := lookupJA4("t13i9999zz_aaaaaaaaaaaa_bbbbbbbbbbbb"); m != nil {
		t.Errorf("unknown fingerprint matched %+v", m)
	}
	if m := lookupJA4(""); m != nil {
		t.Errorf("empty JA4 matched %+v", m)
	}
}

// A UA that contradicts the database verdict must be reported as spoofed and
// the database's answer must win.
func TestIdentifyClient_JA4DBChromeWithCurlUA(t *testing.T) {
	hello := ch("t13d1516h2_8daaf6152771_d8a2da3f94cd", "", true, "h2", "http/1.1")
	got := identifyClient(hello, "curl/8.5.0")
	if got == nil {
		t.Fatal("identifyClient returned nil")
	}
	if !got.Spoofed {
		t.Errorf("Chrome fingerprint + curl UA must be spoofed: %+v", got)
	}
	if got.Name != "Chrome" || got.Family != "browser" {
		t.Errorf("spoofed identity must come from the fingerprint, got %s/%s", got.Name, got.Family)
	}
	if got.Source != "ja4db" {
		t.Errorf("source = %q, want ja4db", got.Source)
	}
	if got.DBObservations == 0 {
		t.Errorf("db_observations should be reported")
	}
}

// A fingerprint we measured ourselves but that JA4DB shows as shared must say
// so instead of pretending the TLS layer settles it.
func TestIdentifyClient_SharedFingerprintIsExplained(t *testing.T) {
	// Go 1.24+ post-quantum hello; JA4DB also sees Chrome-class clients using it.
	// Cover both observed PQ variants: with SNI (d) and dialing an IP literal (i,
	// no SNI, no ALPN) — an honest Go client must never be flagged spoofed.
	for _, ja4 := range []string{
		"t13d131100_f57a46bbacb6_ab7e3b40a677",
		"t13i131000_f57a46bbacb6_ab7e3b40a677",
	} {
		hello := ch(ja4, "9b7dcdf3f997f1fb7b4409c94cb7ef36", false)
		got := identifyClient(hello, "Go-http-client/1.1")
		if got == nil {
			t.Fatal("identifyClient returned nil")
		}
		if got.Spoofed {
			t.Errorf("Go TLS + Go UA must not be spoofed for %s: %+v", ja4, got)
		}
		if len(got.Candidates) < 2 {
			t.Fatalf("expected multiple candidates for a shared fingerprint %s, got %v", ja4, got.Candidates)
		}
		found := false
		for _, n := range got.Notes {
			if strings.Contains(n, "shared") {
				found = true
			}
		}
		if !found {
			t.Errorf("a shared fingerprint must carry a note, got %v", got.Notes)
		}
	}
}

func TestSplitAppLabel(t *testing.T) {
	cases := []struct{ in, name, version string }{
		{"Chrome 42.0", "Chrome", "42.0"},
		{"Samsung Internet 12", "Samsung Internet", "12"},
		{"Chromium Browser", "Chromium Browser", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		n, v := splitAppLabel(c.in)
		if n != c.name || v != c.version {
			t.Errorf("splitAppLabel(%q) = (%q,%q), want (%q,%q)", c.in, n, v, c.name, c.version)
		}
	}
	if got := familyForName("Samsung Internet"); got != "browser" {
		t.Errorf("familyForName(Samsung Internet) = %q, want browser", got)
	}
	if got := familyForName("Telnet"); got != "" {
		t.Errorf("familyForName(Telnet) = %q, want empty", got)
	}
}
