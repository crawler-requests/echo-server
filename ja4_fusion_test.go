package main

import (
	"encoding/json"
	"testing"
)

// The built-in library is a fusion of the JA4DB crowd snapshot and the curated
// FoxIO mapping. These assertions pin the properties that make that fusion
// worth shipping: the malware families only the curated source knows about,
// the OS/library context the crowd rows carry, and the source attribution.
func TestFusedLibrary_ContainsCuratedMalware(t *testing.T) {
	var f dbFile
	if err := json.Unmarshal(ja4dbJSON, &f); err != nil {
		t.Fatalf("embedded library is unreadable: %v", err)
	}
	if len(f.JA4) < 1000 {
		t.Fatalf("library has only %d fingerprints; the snapshot looks truncated", len(f.JA4))
	}

	// Fingerprints that appear ONLY because FoxIO's mapping supplied them.
	want := map[string]string{
		"t13d201100_2b729b4bf6f3_9e7b989ebec8": "IcedID",
		"t12d190800_d83cc789557e_16bbda4055b2": "Cobalt Strike",
		"t13i190800_9dc949149365_97f8aa674fd9": "Sliver",
	}
	for fp, name := range want {
		e := f.JA4[fp]
		if e == nil {
			t.Fatalf("%s fingerprint missing from the fused library", name)
		}
		found := false
		for _, a := range e.Apps {
			if len(a.Label) >= len(name) && a.Label[:len(name)] == name {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s fingerprint does not name %q (apps: %v)", name, name, e.Apps)
		}
	}
}

// Every fingerprint must carry at least one observation after fusion: a
// curated-only entry used to come out with n=0, which the console renders as
// "0 observations" for a match we are confident about.
func TestFusedLibrary_NoZeroObservationEntries(t *testing.T) {
	var f dbFile
	if err := json.Unmarshal(ja4dbJSON, &f); err != nil {
		t.Fatal(err)
	}
	zero := 0
	for fp, e := range f.JA4 {
		if e.N == 0 {
			zero++
			if zero <= 3 {
				t.Errorf("%s has 0 observations", fp)
			}
		}
	}
	if zero > 0 {
		t.Fatalf("%d fingerprints have 0 observations", zero)
	}
}

// The malware/tunnel families are what an operator acts on; they must survive
// the family mapping instead of falling into "unknown".
func TestFamilyForName_MalwareAndTunnel(t *testing.T) {
	cases := map[string]string{
		"Cobalt Strike v4.9.1 beacon": "malware",
		"Sliver Agent":                "malware",
		"IcedID":                      "malware",
		"Qakbot C2":                   "malware",
		"Lumma Client":                "malware",
		"Pikabot C2":                  "malware",
		"Darkgate Client":             "malware",
		"SoftEther VPN Client":        "tunnel",
		"ngrok 3.8.0":                 "tunnel",
		"Chrome":                      "browser",
		"curl":                        "cli",
		"GoLang":                      "runtime",
	}
	for name, want := range cases {
		if got := familyForName(name); got != want {
			t.Errorf("familyForName(%q) = %q, want %q", name, got, want)
		}
	}
}

// OS/library hints must reach the public ClientInfo, not be dropped after
// parsing (they were previously parsed and thrown away).
func TestDBMatchCarriesOSAndLibraryHints(t *testing.T) {
	var f dbFile
	if err := json.Unmarshal(ja4dbJSON, &f); err != nil {
		t.Fatal(err)
	}
	lib := buildLib("builtin", &f)
	if lib == nil {
		t.Fatal("buildLib returned nil")
	}
	// The Chrome fingerprint has a very large submission history with OS rows.
	a := lib.exact["t13d1516h2_8daaf6152771_02713d6af862"]
	if a == nil {
		t.Fatal("Chrome fingerprint missing")
	}
	if len(a.osHints) == 0 {
		t.Fatal("OS hints were not carried into the aggregate")
	}
	m := aggToMatch(a, true)
	if m == nil || len(m.OS) == 0 {
		t.Fatalf("match lost the OS hints: %+v", m)
	}
}
