package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// HTTP/2 fingerprinting.
//
// A TLS fingerprint (JA3/JA4) identifies the TLS stack; the HTTP/2 layer has an
// independent fingerprint that survives TLS impersonation. Anti-bot vendors
// (Akamai first among them) fingerprint clients on:
//
//  1. the SETTINGS frame: which setting IDs are sent, in what order, with what
//     values,
//  2. the PRIORITY frames: whether the client reprioritizes streams, and how,
//  3. the request pseudo-header order (:method, :path, :authority, :scheme).
//
// Go's net/http discards SETTINGS and PRIORITY entirely, and x/net/http2 hides
// them behind its server loop, so the frames are tapped off the raw connection
// before the HTTP/2 server consumes them.
//
// Fingerprint string format (the widely used "Akamai" ordering):
//
//	SETTINGS|PRIORITY|PSEUDO
//
// e.g. `1:65536,2:0,3:100,4:1048576,6:262144|0:1:0|:method,:path,:authority,:scheme`
//
// SETTINGS is `id:value` pairs in wire order; PRIORITY is `streamID:weight:flags`
// per rep-PRIORITY frame; PSEUDO is this request's pseudo-header order.

const (
	h2FrameSettings     = 0x4
	h2FramePriority     = 0x2
	h2FrameHeaders      = 0x1
	h2FrameContinuation = 0x9

	h2FlagHeadersEndHeaders = 0x4
	h2FlagHeadersPadded     = 0x8
	h2FlagHeadersPriority   = 0x20
	h2FlagHeadersEndStream  = 0x1

	// maxH2FrameBuffer bounds reassembly of a partially received frame; a
	// HEADERS frame can legitimately be large, but 1 MB is far beyond any
	// real request head.
	maxH2FrameBuffer = 1 << 20
	// maxH2PseudoOrders caps per-connection pseudo-order bookkeeping.
	maxH2PseudoOrders = 256
)

// h2SettingsEntry is one SETTINGS id/value pair in wire order.
type h2SettingsEntry struct {
	ID    uint16
	Value uint32
}

// h2PriorityEntry is one rep-PRIORITY frame.
type h2PriorityEntry struct {
	StreamID uint32
	Weight   uint8
	Flags    uint8 // 0x1 = exclusive dependency
}

// h2Fingerprint is the per-request view of the connection fingerprint.
type h2Fingerprint struct {
	Raw               string   `json:"raw"`
	Settings          string   `json:"settings,omitempty"`
	Priority          string   `json:"priority,omitempty"`
	PseudoHeaderOrder []string `json:"pseudo_header_order,omitempty"`
	StreamID          uint32   `json:"stream_id,omitempty"`
}

// h2PseudoRecord is the pseudo-header order of one request, with the stream it
// arrived on (so the echo response can report stream_id).
type h2PseudoRecord struct {
	Order    []string
	StreamID uint32
}

// h2Capture is the per-connection recorder shared by every stream.
type h2Capture struct {
	mu            sync.Mutex
	settings      []h2SettingsEntry
	priorities    []h2PriorityEntry
	pseudo        map[string]h2PseudoRecord // "method path" -> order + stream
	lastPseudo    h2PseudoRecord
	prefaceFrames int
}

func newH2Capture() *h2Capture {
	return &h2Capture{pseudo: map[string]h2PseudoRecord{}}
}

func (c *h2Capture) recordSettings(ids []uint16, values []uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, id := range ids {
		if i >= len(values) {
			break
		}
		// Later SETTINGS frames for the same id update the value; the wire
		// position of the first occurrence is what the fingerprint records.
		for j := range c.settings {
			if c.settings[j].ID == id {
				c.settings[j].Value = values[i]
				goto next
			}
		}
		c.settings = append(c.settings, h2SettingsEntry{ID: id, Value: values[i]})
	next:
	}
}

func (c *h2Capture) recordPriority(p h2PriorityEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.priorities = append(c.priorities, p)
}

func (c *h2Capture) recordPseudo(key string, order []string, streamID uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := h2PseudoRecord{Order: order, StreamID: streamID}
	if len(c.pseudo) < maxH2PseudoOrders {
		c.pseudo[key] = rec
	}
	c.lastPseudo = rec
}

func (c *h2Capture) bumpFrames() {
	c.mu.Lock()
	c.prefaceFrames++
	c.mu.Unlock()
}

func (c *h2Capture) settingsString() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	parts := make([]string, len(c.settings))
	for i, s := range c.settings {
		parts[i] = fmt.Sprintf("%d:%d", s.ID, s.Value)
	}
	return strings.Join(parts, ",")
}

func (c *h2Capture) priorityString() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	parts := make([]string, len(c.priorities))
	for i, p := range c.priorities {
		parts[i] = fmt.Sprintf("%d:%d:%d", p.StreamID, p.Weight, p.Flags)
	}
	return strings.Join(parts, ",")
}

func (c *h2Capture) pseudoFor(method, path string) h2PseudoRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rec, ok := c.pseudo[method+" "+path]; ok {
		return h2PseudoRecord{Order: append([]string(nil), rec.Order...), StreamID: rec.StreamID}
	}
	return h2PseudoRecord{Order: append([]string(nil), c.lastPseudo.Order...), StreamID: c.lastPseudo.StreamID}
}

func (c *h2Capture) fingerprint(method, path string) h2Fingerprint {
	s := c.settingsString()
	pr := c.priorityString()
	rec := c.pseudoFor(method, path)
	pseudo := rec.Order
	f := h2Fingerprint{Settings: s, Priority: pr, PseudoHeaderOrder: pseudo, StreamID: rec.StreamID}
	var parts []string
	if s != "" {
		parts = append(parts, s)
	}
	if pr != "" {
		parts = append(parts, pr)
	}
	parts = append(parts, strings.Join(pseudo, ","))
	f.Raw = strings.Join(parts, "|")
	return f
}

// h2CtxKey carries the *h2Capture to every request on the connection.
type h2CtxKey struct{}

func h2CaptureFromRequest(r *http.Request) *h2Capture {
	c, _ := r.Context().Value(h2CtxKey{}).(*h2Capture)
	return c
}

// h2SniffConn tees the client-to-server byte stream so frames can be recorded
// without disturbing the HTTP/2 server that reads the same bytes.
//
// The HTTP/2 connection preface (24 magic bytes) is skipped, then SETTINGS,
// PRIORITY, HEADERS and CONTINUATION frames are parsed in order. HPACK blocks
// are decoded with one decoder per connection, which is required because the
// HPACK dynamic table is connection state.
type h2SniffConn struct {
	net.Conn
	cap *h2Capture

	mu       sync.Mutex
	buf      []byte // partial frame bytes
	prefaced bool   // 24-byte client preface consumed
	hpack    *hpack.Decoder
	block    []byte // accumulated header block across CONTINUATION frames
}

var h2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

func newH2SniffConn(c net.Conn, cap *h2Capture) *h2SniffConn {
	s := &h2SniffConn{Conn: c, cap: cap, hpack: hpack.NewDecoder(4096, nil)}
	return s
}

// Read returns the bytes untouched and feeds a copy to the frame parser.
func (s *h2SniffConn) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	if n > 0 {
		s.feed(p[:n])
	}
	return n, err
}

func (s *h2SniffConn) feed(chunk []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buf)+len(chunk) > maxH2FrameBuffer {
		// Garbage or a pathological peer; stop recording but keep serving.
		s.buf = nil
		return
	}
	s.buf = append(s.buf, chunk...)

	if !s.prefaced {
		if len(s.buf) < len(h2ClientPreface) {
			return
		}
		if string(s.buf[:len(h2ClientPreface)]) != string(h2ClientPreface) {
			// Not an HTTP/2 client; nothing to fingerprint.
			s.buf = nil
			s.prefaced = true
			return
		}
		s.buf = s.buf[len(h2ClientPreface):]
		s.prefaced = true
	}

	for {
		if len(s.buf) < 9 {
			return
		}
		length := int(s.buf[0])<<16 | int(s.buf[1])<<8 | int(s.buf[2])
		if length < 0 || length > maxH2FrameBuffer {
			s.buf = nil
			return
		}
		if len(s.buf) < 9+length {
			return
		}
		typ := s.buf[3]
		flags := s.buf[4]
		streamID := uint32(s.buf[5]&0x7f)<<24 | uint32(s.buf[6])<<16 | uint32(s.buf[7])<<8 | uint32(s.buf[8])
		payload := s.buf[9 : 9+length]
		s.buf = s.buf[9+length:]

		s.handleFrame(typ, flags, streamID, payload)
	}
}

func (s *h2SniffConn) handleFrame(typ byte, flags byte, streamID uint32, payload []byte) {
	s.cap.bumpFrames()
	switch typ {
	case h2FrameSettings:
		if streamID != 0 || len(payload)%6 != 0 {
			return
		}
		var ids []uint16
		var vals []uint32
		for i := 0; i+6 <= len(payload); i += 6 {
			ids = append(ids, uint16(payload[i])<<8|uint16(payload[i+1]))
			vals = append(vals, uint32(payload[i+2])<<24|uint32(payload[i+3])<<16|uint32(payload[i+4])<<8|uint32(payload[i+5]))
		}
		s.cap.recordSettings(ids, vals)

	case h2FramePriority:
		if streamID == 0 || len(payload) != 5 {
			return
		}
		flags := byte(0)
		if payload[0]&0x80 != 0 {
			flags = 1
		}
		s.cap.recordPriority(h2PriorityEntry{
			StreamID: streamID,
			Weight:   payload[4],
			Flags:    flags,
		})

	case h2FrameHeaders:
		block := payload
		if flags&h2FlagHeadersPadded != 0 {
			if len(block) < 1 {
				return
			}
			pad := int(block[0])
			block = block[1:]
			if pad > len(block) {
				return
			}
			block = block[:len(block)-pad]
		}
		if flags&h2FlagHeadersPriority != 0 {
			pflags := byte(0)
			if len(block) >= 4 && block[0]&0x80 != 0 {
				pflags = 1
			}
			if len(block) < 5 {
				return
			}
			s.cap.recordPriority(h2PriorityEntry{
				StreamID: streamID,
				Weight:   block[4],
				Flags:    pflags,
			})
			block = block[5:]
		}
		if len(block) > 0 {
			s.block = append(s.block, block...)
		}
		if flags&h2FlagHeadersEndHeaders != 0 {
			s.finishHeaderBlock(streamID)
		}

	case h2FrameContinuation:
		if len(payload) > 0 {
			s.block = append(s.block, payload...)
		}
		if flags&h2FlagHeadersEndHeaders != 0 {
			s.finishHeaderBlock(streamID)
		}
	}
}

// finishHeaderBlock decodes one complete header block and records the
// pseudo-header order plus the "method path" key used to attach it to a
// request later.
func (s *h2SniffConn) finishHeaderBlock(streamID uint32) {
	block := s.block
	s.block = nil
	if len(block) == 0 {
		return
	}
	var order []string
	var method, path string
	dec := s.hpack
	dec.SetEmitFunc(func(f hpack.HeaderField) {
		switch f.Name {
		case ":method":
			method = f.Value
			order = append(order, ":method")
		case ":path":
			path = f.Value
			order = append(order, ":path")
		case ":authority":
			order = append(order, ":authority")
		case ":scheme":
			order = append(order, ":scheme")
		case ":status", ":protocol":
			order = append(order, f.Name)
		}
	})
	if _, err := dec.Write(block); err != nil {
		return
	}
	// Reset the emit callback so a later block does not append to this one.
	dec.SetEmitFunc(nil)
	if len(order) == 0 {
		return
	}
	s.cap.recordPseudo(method+" "+path, order, streamID)
}

// h2ConnHook returns the http.Server.TLSNextProto handler for "h2". It is
// invoked once per connection that negotiated h2: the capture is per
// connection (one client, one SETTINGS/priority set), the sniffer taps the
// byte stream, and x/net/http2 serves the requests. The handler passed in is
// the same mux as HTTP/1.x, so auth/middleware/echo are unchanged.
func h2ConnHook() func(*http.Server, *tls.Conn, http.Handler) {
	return func(hs *http.Server, tlsConn *tls.Conn, handler http.Handler) {
		cap := newH2Capture()
		ctx := context.WithValue(context.Background(), h2CtxKey{}, cap)
		ctx = context.WithValue(ctx, echoCtxKey{}, tlsConn.NetConn())

		sniff := newH2SniffConn(tlsConn, cap)
		srv := &http2.Server{}
		opts := &http2.ServeConnOpts{
			Context:    ctx,
			Handler:    handler,
			BaseConfig: hs,
		}
		srv.ServeConn(sniff, opts)
	}
}

// ensure io is referenced for the ConnReader-like contract above.
var _ io.Reader = (*h2SniffConn)(nil)

// h2SniffEnabled reports whether the operator wants HTTP/2 handled locally.
// Disabling it falls back to HTTP/1.1-only ALPN.
func h2SniffEnabled() bool { return GetConfig("enable_http2") != "false" }

// parseUint32OrZero is a small helper for tests and settings rendering.
func parseUint32OrZero(s string) uint32 {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}
