package main

import (
	"testing"
)

// The container HEALTHCHECK runs `echo-server healthcheck`, so the probe must
// resolve the listener from the same environment the server reads. The bug it
// replaces: a hard-coded 127.0.0.1:23231 probe reported "unhealthy" forever
// whenever HTTP_PORT was 0 (HTTPS-only) or moved to another port.
//
// The probe is injected (healthcheckWithProbe), so these tests record every
// URL the probe would dial. That makes "the disabled listener is never dialed"
// an assertion rather than an inference.
type probeRecorder struct {
	dialed  []string
	healthy map[string]bool
}

func (p *probeRecorder) probe(base string) bool {
	p.dialed = append(p.dialed, base)
	return p.healthy[base]
}

func TestHealthcheckHttpsOnlyDoesNotDialDisabledPlainPort(t *testing.T) {
	p := &probeRecorder{healthy: map[string]bool{"https://127.0.0.1:26232": true}}
	t.Setenv("PORT", "26232")
	t.Setenv("HTTP_PORT", "0")

	if code := healthcheckWithProbe(p.probe); code != 0 {
		t.Fatalf("healthcheckWithProbe = %d; want 0 against a live HTTPS-only server", code)
	}
	for _, base := range p.dialed {
		if base == "http://127.0.0.1:23231" {
			t.Fatalf("probe dialed the disabled plain listener: %v", p.dialed)
		}
	}
}

func TestHealthcheckMovedPlainPort(t *testing.T) {
	p := &probeRecorder{healthy: map[string]bool{"http://127.0.0.1:8080": true}}
	t.Setenv("PORT", "26232")
	t.Setenv("HTTP_PORT", "8080")

	if code := healthcheckWithProbe(p.probe); code != 0 {
		t.Fatalf("healthcheckWithProbe = %d; want 0 via the moved plain listener", code)
	}
	found := false
	for _, base := range p.dialed {
		if base == "http://127.0.0.1:8080" {
			found = true
		}
		if base == "http://127.0.0.1:23231" {
			t.Fatalf("probe fell back to the default plain port instead of the configured one: %v", p.dialed)
		}
	}
	if !found {
		t.Fatalf("probe never dialed the configured plain port: %v", p.dialed)
	}
}

func TestHealthcheckFailsWhenNothingAnswers(t *testing.T) {
	p := &probeRecorder{healthy: map[string]bool{}}
	t.Setenv("PORT", "26232")
	t.Setenv("HTTP_PORT", "26231")

	if code := healthcheckWithProbe(p.probe); code != 1 {
		t.Fatalf("healthcheckWithProbe = %d; want 1 when no listener answers", code)
	}
	if len(p.dialed) != 2 {
		t.Fatalf("probe dialed %d listeners; want both HTTPS and plain before giving up: %v", len(p.dialed), p.dialed)
	}
}

func TestHealthcheckOffSpellings(t *testing.T) {
	for _, port := range []string{"23231", "8080", "1"} {
		if !listenerEnabled(port) {
			t.Errorf("listenerEnabled(%q) = false; want true", port)
		}
	}
	for _, port := range []string{"0", "off", "OFF", "Off"} {
		if listenerEnabled(port) {
			t.Errorf("listenerEnabled(%q) = true; want false (disabled)", port)
		}
	}
}

func TestHealthcheckDefaultsWhenUnset(t *testing.T) {
	// Unset is the plain container default: the probe tries the two documented
	// default ports, HTTPS first.
	var dialed []string
	probe := func(base string) bool {
		dialed = append(dialed, base)
		return base == "https://127.0.0.1:23232"
	}
	t.Setenv("PORT", "")
	t.Setenv("HTTP_PORT", "")
	if code := healthcheckWithProbe(probe); code != 0 {
		t.Fatalf("healthcheckWithProbe = %d; want 0 against the default HTTPS port", code)
	}
	if len(dialed) == 0 || dialed[0] != "https://127.0.0.1:23232" {
		t.Fatalf("probe dialed %v; want HTTPS first on the default port", dialed)
	}
}
