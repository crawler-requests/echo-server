package main

import (
	"net"
	"net/http"
	"sync"
)

const (
	// maxHelloBufferBytes bounds how many raw bytes a single connection may
	// buffer while reassembling its ClientHello. A ClientHello is normally
	// well under 4 KB; post-quantum hybrid hellos are ~2 KB. 64 KB is far
	// beyond any legitimate case and protects the server from a client that
	// opens a connection and streams garbage without ever completing a record.
	maxHelloBufferBytes = 64 << 10
	// maxHelloRecords bounds how many TLS records we will stitch together.
	// A ClientHello legally spans multiple records, but more than a handful
	// indicates something that is not a ClientHello.
	maxHelloRecords = 16
)

// echoCtxKey is the context key under which http.Server.ConnContext stores the
// underlying net.Conn for a request, so the echo handler can read the
// ClientHello captured for exactly that connection.
type echoCtxKey struct{}

// helloConnFromRequest returns the helloConn bound to r's connection, or nil
// when the server does not expose it (e.g. httptest.NewRequest).
func helloConnFromRequest(r *http.Request) *helloConn {
	c, ok := r.Context().Value(echoCtxKey{}).(net.Conn)
	if !ok {
		return nil
	}
	hc, ok := c.(*helloConn)
	if !ok {
		return nil
	}
	return hc
}

// helloSnapshotFromConn returns the full capture for this request's
// connection, or an empty snapshot when unavailable.
func helloSnapshotFromConn(r *http.Request) helloSnapshot {
	if hc := helloConnFromRequest(r); hc != nil {
		return hc.Snapshot()
	}
	return helloSnapshot{}
}

// helloFromConn returns the ClientHello handshake message bound to this
// request's connection, or nil when unavailable.
func helloFromConn(r *http.Request) []byte {
	return helloSnapshotFromConn(r).Payload
}

// capturedHello keeps the last captured ClientHello payload as a FALLBACK.
// Production traffic carries the hello per-connection via helloConn; the
// global is only written by tests (and historical code) and read when no
// connection-bound hello is available, so concurrent requests never race.
var (
	capturedHello     []byte
	capturedHelloLock sync.Mutex
)

// helloListener wraps a net.Listener and binds each accepted connection to a
// helloConn that captures the ClientHello before the TLS handshake consumes it.
type helloListener struct {
	net.Listener
}

func (l *helloListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &helloConn{Conn: conn}, nil
}

// helloConn captures the TLS ClientHello as it is read from the socket.
//
// TCP does not preserve record boundaries: the crypto/tls layer issues reads
// whose sizes depend on socket timing, and a large ClientHello (e.g. one with
// a post-quantum key share) routinely arrives split across several reads. The
// capture therefore ACCUMULATES bytes across reads and parses incrementally,
// instead of assuming the first read holds a whole record.
type helloConn struct {
	net.Conn

	mu      sync.Mutex
	buf     []byte   // untconsumed bytes read from the socket
	records [][]byte // complete TLS records collected so far
	hs      []byte   // reassembled record payloads (handshake byte stream)
	payload []byte   // complete ClientHello message (handshake header included)
	done    bool     // capture finished (found the hello, or gave up)
}

func (c *helloConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.capture(b[:n])
	}
	return n, err
}

// capture appends a fresh chunk and advances the incremental parser.
func (c *helloConn) capture(chunk []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	if len(c.buf)+len(chunk) > maxHelloBufferBytes {
		c.giveUp()
		return
	}
	c.buf = append(c.buf, chunk...)
	c.parse()
}

// parse consumes as many complete TLS records/messages as the buffer holds.
// It returns with done=false when it needs more bytes, which is the normal
// case mid-handshake.
func (c *helloConn) parse() {
	for !c.done {
		if len(c.hs) >= 4 && c.hs[0] != 0x01 {
			// First handshake message from a client must be a ClientHello.
			c.giveUp()
			return
		}
		if len(c.hs) >= 4 {
			msgLen := int(c.hs[1])<<16 | int(c.hs[2])<<8 | int(c.hs[3])
			if msgLen < 0 || msgLen+4 > maxHelloBufferBytes {
				c.giveUp()
				return
			}
			if len(c.hs) >= 4+msgLen {
				c.payload = append([]byte(nil), c.hs[:4+msgLen]...)
				c.done = true
				c.buf, c.hs = nil, nil // release memory; the hello is what we keep
				return
			}
		}
		// Need another record to complete the handshake message.
		if len(c.buf) < 5 {
			return
		}
		if c.buf[0] != 22 { // not a handshake record
			c.giveUp()
			return
		}
		recLen := int(c.buf[3])<<8 | int(c.buf[4])
		if recLen == 0 || recLen > 1<<14+2048 { // max TLSPlaintext + overhead
			c.giveUp()
			return
		}
		if len(c.buf) < 5+recLen {
			return // record still arriving
		}
		if len(c.records) >= maxHelloRecords {
			c.giveUp()
			return
		}
		rec := append([]byte(nil), c.buf[:5+recLen]...)
		c.records = append(c.records, rec)
		c.hs = append(c.hs, rec[5:]...)
		c.buf = c.buf[5+recLen:]
	}
}

// giveUp stops capturing without storing a partial hello.
func (c *helloConn) giveUp() {
	c.done = true
	c.buf, c.hs = nil, nil
}

// helloSnapshot is an immutable view of the capture for one request.
type helloSnapshot struct {
	Payload       []byte   // ClientHello message, handshake header included
	Records       [][]byte // TLS records that carried it, in wire order
	RecordVersion uint16   // version field of the first record (0 if none)
}

// RecordBytes returns all records concatenated (header included).
func (s helloSnapshot) RecordBytes() []byte {
	if len(s.Records) == 0 {
		return nil
	}
	if len(s.Records) == 1 {
		return s.Records[0]
	}
	var out []byte
	for _, r := range s.Records {
		out = append(out, r...)
	}
	return out
}

// RecordCount is the number of TLS records the ClientHello spanned.
func (s helloSnapshot) RecordCount() int { return len(s.Records) }

// Snapshot returns a copy of the current capture. Safe to call concurrently
// with the handshake goroutine.
func (c *helloConn) Snapshot() helloSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	snap := helloSnapshot{}
	if len(c.payload) > 0 {
		snap.Payload = append([]byte(nil), c.payload...)
	}
	if len(c.records) > 0 {
		snap.Records = make([][]byte, len(c.records))
		for i, r := range c.records {
			snap.Records[i] = append([]byte(nil), r...)
		}
		snap.RecordVersion = uint16(c.records[0][1])<<8 | uint16(c.records[0][2])
	}
	return snap
}

// HelloRecord returns all TLS record bytes (concatenated) or nil.
func (c *helloConn) HelloRecord() []byte { return c.Snapshot().RecordBytes() }

// HelloPayload returns the ClientHello message without record headers, or nil.
func (c *helloConn) HelloPayload() []byte { return c.Snapshot().Payload }

// wrapListener returns a listener that captures ClientHello before TLS handshake.
func wrapListener(l net.Listener) net.Listener {
	return &helloListener{Listener: l}
}

// getCapturedClientHello returns a copy of the fallback global ClientHello.
func getCapturedClientHello() []byte {
	capturedHelloLock.Lock()
	defer capturedHelloLock.Unlock()
	if capturedHello == nil {
		return nil
	}
	cp := make([]byte, len(capturedHello))
	copy(cp, capturedHello)
	return cp
}
