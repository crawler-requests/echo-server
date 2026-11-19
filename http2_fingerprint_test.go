package main

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func TestH2Capture_SettingsOrderAndValues(t *testing.T) {
	cap := newH2Capture()
	// A curl-shaped SETTINGS frame: header table size, max concurrent, etc.
	cap.recordSettings([]uint16{3, 4, 2}, []uint32{100, 10485760, 0})
	if got := cap.settingsString(); got != "3:100,4:10485760,2:0" {
		t.Fatalf("settings = %q", got)
	}

	// A later SETTINGS frame that repeats an id updates the value but must not
	// duplicate the position: the fingerprint order is a client trait.
	cap.recordSettings([]uint16{4, 5}, []uint32{2097152, 16384})
	if got := cap.settingsString(); got != "3:100,4:2097152,2:0,5:16384" {
		t.Fatalf("settings after update = %q", got)
	}
}

func TestH2Capture_PriorityAndPseudo(t *testing.T) {
	cap := newH2Capture()
	cap.recordPriority(h2PriorityEntry{StreamID: 1, Weight: 220, Flags: 0})
	if got := cap.priorityString(); got != "1:220:0" {
		t.Fatalf("priority = %q", got)
	}

	cap.recordPseudo("GET /echo", []string{":method", ":path", ":authority", ":scheme"}, 3)
	fp := cap.fingerprint("GET", "/echo")
	// With a PRIORITY frame captured the raw string is
	// SETTINGS|PRIORITY|PSEUDO; only the pseudo part is asserted here.
	if !strings.HasSuffix(fp.Raw, ":method,:path,:authority,:scheme") {
		t.Fatalf("raw = %q", fp.Raw)
	}
	if fp.StreamID != 3 {
		t.Fatalf("stream = %d, want 3", fp.StreamID)
	}
}

func TestH2Capture_DistinguishesKnownClients(t *testing.T) {
	// curl and Go's stdlib emit different SETTINGS and pseudo-header orders;
	// the fingerprint must reflect both, not normalise them away.
	curl := newH2Capture()
	curl.recordSettings([]uint16{3, 4, 2}, []uint32{100, 10485760, 0})
	curl.recordPseudo("GET /echo", []string{":method", ":scheme", ":authority", ":path"}, 1)

	goClient := newH2Capture()
	goClient.recordSettings([]uint16{2, 4, 5, 6}, []uint32{0, 4194304, 16384, 10485760})
	goClient.recordPseudo("GET /echo", []string{":authority", ":method", ":path", ":scheme"}, 1)

	cf := curl.fingerprint("GET", "/echo").Raw
	gf := goClient.fingerprint("GET", "/echo").Raw
	if cf == gf {
		t.Fatalf("curl and Go fingerprints collided: %q", cf)
	}
	if !strings.Contains(cf, ":method,:scheme,:authority,:path") {
		t.Fatalf("curl pseudo order lost: %q", cf)
	}
	if !strings.Contains(gf, ":authority,:method,:path,:scheme") {
		t.Fatalf("go pseudo order lost: %q", gf)
	}
}

// TestH2SniffConn_ParsesFrames feeds a synthetic preface + SETTINGS + HEADERS
// through the sniffer and checks the capture, independent of a real socket.
func TestH2SniffConn_ParsesFrames(t *testing.T) {
	cap := newH2Capture()

	settings := frame(h2FrameSettings, 0, 0, []byte{
		0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // id 3 = 100
		0x00, 0x04, 0x00, 0xa0, 0x00, 0x00, // id 4 = 10485760
	})
	priority := frame(h2FramePriority, 0, 1, []byte{0x00, 0x00, 0x00, 0x00, 0xdc})

	// A minimal HPACK block: indexed pseudo-headers from the static table
	// (:method GET = 0x82, :path / = 0x84) plus a literal :authority.
	// Using hpack encoding from x/net keeps this honest.
	block := hpackEncode(t, []struct{ name, value string }{
		{":method", "GET"}, {":scheme", "https"}, {":authority", "example.com"}, {":path", "/echo"},
	})
	headers := frame(h2FrameHeaders, h2FlagHeadersEndHeaders, 1, block)

	var stream strings.Builder
	stream.Write(h2ClientPreface)
	stream.Write(settings)
	stream.Write(priority)
	stream.Write(headers)

	sc := &h2SniffConn{cap: cap, hpack: newHpackDecoder()}
	sc.feed([]byte(stream.String()))

	fp := cap.fingerprint("GET", "/echo")
	if !strings.Contains(fp.Settings, "3:100") || !strings.Contains(fp.Settings, "4:10485760") {
		t.Fatalf("settings not parsed: %q", fp.Settings)
	}
	if fp.Priority == "" {
		t.Fatalf("priority frame not parsed")
	}
	if len(fp.PseudoHeaderOrder) != 4 || fp.PseudoHeaderOrder[0] != ":method" {
		t.Fatalf("pseudo order = %v", fp.PseudoHeaderOrder)
	}
	if fp.StreamID != 1 {
		t.Fatalf("stream id = %d", fp.StreamID)
	}
}

// frame builds one HTTP/2 frame for the parser tests.
func frame(typ byte, flags byte, streamID uint32, payload []byte) []byte {
	b := make([]byte, 9+len(payload))
	b[0] = byte(len(payload) >> 16)
	b[1] = byte(len(payload) >> 8)
	b[2] = byte(len(payload))
	b[3] = typ
	b[4] = flags
	b[5] = byte(streamID >> 24)
	b[6] = byte(streamID >> 16)
	b[7] = byte(streamID >> 8)
	b[8] = byte(streamID)
	copy(b[9:], payload)
	return b
}

// hpackEncode encodes header fields with a fresh HPACK encoder (static-table
// indexing is what a real client does for the common pseudo-headers).
func hpackEncode(t *testing.T, fields []struct{ name, value string }) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range fields {
		if err := enc.WriteField(hpack.HeaderField{Name: f.name, Value: f.value}); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

// newHpackDecoder returns a decoder equivalent to the one the sniffer creates.
func newHpackDecoder() *hpack.Decoder { return hpack.NewDecoder(4096, nil) }
