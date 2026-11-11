package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- ClientHello builders ----------------------------------------------------

type extSpec struct {
	typ  uint16
	data []byte
}

// helloSpec describes a ClientHello to synthesize for tests.
type helloSpec struct {
	legacyVersion uint16
	ciphers       []uint16
	compression   []byte
	exts          []extSpec
}

func u16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func u16s(vs ...uint16) []byte {
	var b []byte
	for _, v := range vs {
		b = append(b, u16(v)...)
	}
	return b
}

// buildHello returns the ClientHello handshake message (header included).
func buildHello(spec helloSpec) []byte {
	if spec.legacyVersion == 0 {
		spec.legacyVersion = 0x0303
	}
	if spec.compression == nil {
		spec.compression = []byte{0}
	}
	var body []byte
	body = append(body, u16(spec.legacyVersion)...)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id length
	cs := u16s(spec.ciphers...)
	body = append(body, u16(uint16(len(cs)))...)
	body = append(body, cs...)
	body = append(body, byte(len(spec.compression)))
	body = append(body, spec.compression...)
	if len(spec.exts) > 0 {
		var exts []byte
		for _, e := range spec.exts {
			exts = append(exts, u16(e.typ)...)
			exts = append(exts, u16(uint16(len(e.data)))...)
			exts = append(exts, e.data...)
		}
		body = append(body, u16(uint16(len(exts)))...)
		body = append(body, exts...)
	}
	msg := append([]byte{0x01}, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	return append(msg, body...)
}

// wrapRecords splits a handshake stream into TLS handshake records of at most
// chunk bytes each (chunk <= 0 means one record for everything).
func wrapRecords(hs []byte, chunk int) []byte {
	if chunk <= 0 || chunk > len(hs) {
		chunk = len(hs)
	}
	var out []byte
	for off := 0; off < len(hs); off += chunk {
		end := off + chunk
		if end > len(hs) {
			end = len(hs)
		}
		part := hs[off:end]
		out = append(out, 0x16, 0x03, 0x01, byte(len(part)>>8), byte(len(part)))
		out = append(out, part...)
	}
	return out
}

func sniExt(host string) extSpec {
	data := []byte{0, 0} // list length placeholder
	entry := append([]byte{0}, u16(uint16(len(host)))...)
	entry = append(entry, []byte(host)...)
	listLen := len(entry)
	data[0], data[1] = byte(listLen>>8), byte(listLen)
	data = append(data, entry...)
	return extSpec{extServerName, data}
}

func alpnExt(protos ...string) extSpec {
	var list []byte
	for _, p := range protos {
		list = append(list, byte(len(p)))
		list = append(list, []byte(p)...)
	}
	data := u16(uint16(len(list)))
	data = append(data, list...)
	return extSpec{extALPN, data}
}

func supportedVersionsExt(versions ...uint16) extSpec {
	payload := u16s(versions...)
	data := append([]byte{byte(len(payload))}, payload...)
	return extSpec{extSupportedVersions, data}
}

func sigAlgsExt(algs ...uint16) extSpec {
	payload := u16s(algs...)
	data := u16(uint16(len(payload)))
	data = append(data, payload...)
	return extSpec{extSignatureAlgorithms, data}
}

func groupsExt(groups ...uint16) extSpec {
	payload := u16s(groups...)
	data := u16(uint16(len(payload)))
	data = append(data, payload...)
	return extSpec{extSupportedGroups, data}
}

func keyShareExt(groups ...uint16) extSpec {
	var entries []byte
	for _, g := range groups {
		entries = append(entries, u16(g)...)
		entries = append(entries, u16(2)...)
		entries = append(entries, 0xaa, 0xbb)
	}
	data := u16(uint16(len(entries)))
	data = append(data, entries...)
	return extSpec{extKeyShare, data}
}

func pointFormatsExt(formats ...byte) extSpec {
	data := append([]byte{byte(len(formats))}, formats...)
	return extSpec{extECPointFormats, data}
}

// --- capture: fragmentation, records ---------------------------------------

// feedConn writes chunks to the peer and reads them all back through a
// helloConn, returning the capture.
func feedConn(t *testing.T, raw []byte, readSize, chunkSize int) *helloConn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close() })

	hc := &helloConn{Conn: server}
	go func() {
		defer client.Close()
		if chunkSize <= 0 {
			client.Write(raw) //nolint:errcheck
			return
		}
		for off := 0; off < len(raw); off += chunkSize {
			end := off + chunkSize
			if end > len(raw) {
				end = len(raw)
			}
			if _, err := client.Write(raw[off:end]); err != nil {
				return
			}
			time.Sleep(time.Millisecond) // let the reader drain this segment
		}
	}()

	buf := make([]byte, readSize)
	total, want := 0, len(raw)
	deadline := time.Now().Add(5 * time.Second)
	for total < want && time.Now().Before(deadline) {
		n, err := hc.Read(buf)
		total += n
		if err != nil && !(err == io.EOF) {
			break
		}
		if n == 0 {
			break
		}
	}
	return hc
}

// TestHelloConn_ReassemblesFragmentedHello is the regression test for the
// original capture bug: net.Conn reads do not align with TLS record
// boundaries, so a ClientHello that arrives in several chunks must still be
// captured in full.
func TestHelloConn_ReassemblesFragmentedHello(t *testing.T) {
	spec := helloSpec{
		ciphers: []uint16{0x1301, 0x1302, 0xc02b},
		exts: []extSpec{
			sniExt("fragmented.example.com"),
			supportedVersionsExt(0x0304, 0x0303),
		},
	}
	hs := buildHello(spec)
	raw := wrapRecords(hs, 0)

	cases := []struct {
		name            string
		readSize, chunk int
	}{
		{"single read", len(raw), 0},
		{"two chunks", len(raw), len(raw) / 2},
		{"small chunks", 16, 7},
		{"one byte at a time", 1, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hc := feedConn(t, raw, c.readSize, c.chunk)
			got := hc.Snapshot().Payload
			if !bytes.Equal(got, hs) {
				t.Fatalf("captured payload differs from sent ClientHello\n got %d bytes\nwant %d bytes", len(got), len(hs))
			}
			if p := parseClientHello(got); p == nil || p.SNI != "fragmented.example.com" {
				t.Errorf("SNI not recovered from reassembled hello: %+v", p)
			}
		})
	}
}

// TestHelloConn_ReassemblesAcrossRecords covers a legal ClientHello split over
// several TLS records.
func TestHelloConn_ReassemblesAcrossRecords(t *testing.T) {
	hs := buildHello(helloSpec{
		ciphers: []uint16{0x1301, 0x1302},
		exts:    []extSpec{sniExt("multi.record.example"), alpnExt("h2")},
	})
	raw := wrapRecords(hs, 40) // several records

	hc := feedConn(t, raw, 11, 13)
	snap := hc.Snapshot()
	if !bytes.Equal(snap.Payload, hs) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(snap.Payload), len(hs))
	}
	if snap.RecordCount() != len(raw)/1 && snap.RecordCount() < 2 {
		t.Errorf("expected the hello to span multiple records, got %d", snap.RecordCount())
	}
	if !bytes.Equal(snap.RecordBytes(), raw) {
		t.Errorf("record bytes were not preserved verbatim")
	}
	if snap.RecordVersion != 0x0301 {
		t.Errorf("record version = %#x, want 0x0301", snap.RecordVersion)
	}
	if p := parseClientHello(snap.Payload); p == nil || len(p.ALPN) != 1 || p.ALPN[0] != "h2" {
		t.Errorf("ALPN not parsed across records: %+v", p)
	}
}

func TestHelloConn_IgnoresNonTLSAndKeepsServing(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	hc := feedConn(t, payload, 4096, 0)
	if len(hc.Snapshot().Payload) != 0 {
		t.Errorf("non-TLS bytes must not be captured as a ClientHello")
	}
}

func TestHelloConn_GivesUpOnOversizedGarbage(t *testing.T) {
	garbage := make([]byte, 4096)
	garbage[0] = 22                     // claims handshake
	garbage[3], garbage[4] = 0xff, 0xff // record length 65535 (too large)
	hc := feedConn(t, garbage, 4096, 0)
	if len(hc.Snapshot().Payload) != 0 {
		t.Errorf("oversized bogus record must not be captured")
	}
}

func TestHelloConn_ConcurrentSnapshot(t *testing.T) {
	hs := buildHello(helloSpec{ciphers: []uint16{0x1301}, exts: []extSpec{sniExt("race.example")}})
	raw := wrapRecords(hs, 0)
	server, client := net.Pipe()
	defer server.Close()
	hc := &helloConn{Conn: server}

	// One reader drains the socket (as crypto/tls would); the others hammer
	// Snapshot concurrently to prove the capture is race-free.
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		buf := make([]byte, 16)
		for {
			if _, err := hc.Read(buf); err != nil {
				return
			}
		}
	}()
	var watchers sync.WaitGroup
	for i := 0; i < 8; i++ {
		watchers.Add(1)
		go func() {
			defer watchers.Done()
			for j := 0; j < 200; j++ {
				_ = hc.Snapshot()
			}
		}()
	}
	client.Write(raw) //nolint:errcheck
	watchers.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := hc.Snapshot().Payload; bytes.Equal(got, hs) {
			client.Close()
			readers.Wait()
			return
		}
		time.Sleep(time.Millisecond)
	}
	client.Close()
	readers.Wait()
	t.Fatalf("payload not captured under concurrent access: got %d bytes, want %d", len(hc.Snapshot().Payload), len(hs))
}

// --- fingerprints ------------------------------------------------------------

// TestJA3_MatchesKnownPublicVector builds a ClientHello equivalent to a
// well-known browser hello and checks the JA3 string and its MD5 against
// externally computed values. This pins both the parser and the hash.
func TestJA3_MatchesKnownPublicVector(t *testing.T) {
	ciphers := []uint16{4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53}
	extTypes := []uint16{0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21}
	exts := make([]extSpec, len(extTypes))
	for i, typ := range extTypes {
		exts[i] = extSpec{typ, nil}
	}
	hs := buildHello(helloSpec{
		ciphers: ciphers,
		exts:    exts,
	})
	// supported_groups (ext 10) must carry the curve list for JA3.
	for i := range exts {
		switch exts[i].typ {
		case extSupportedGroups:
			exts[i] = groupsExt(29, 23, 24)
		case extECPointFormats:
			exts[i] = pointFormatsExt(0)
		}
	}
	hs = buildHello(helloSpec{ciphers: ciphers, exts: exts})

	ja3, hash := computeJA3(hs)
	want := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53," +
		"0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
	if ja3 != want {
		t.Fatalf("JA3 string mismatch\n got %s\nwant %s", ja3, want)
	}
	sum := md5.Sum([]byte(want))
	if wantHash := hex.EncodeToString(sum[:]); hash != wantHash {
		t.Errorf("JA3 hash = %s, want real MD5 %s", hash, wantHash)
	}
	// b32309a26951912be7dba376398abc3b is the MD5 of the string above,
	// verified independently with Python's hashlib.
	if hash != "b32309a26951912be7dba376398abc3b" {
		t.Errorf("JA3 hash drifted from the known public value: %s", hash)
	}
}

func TestJA4_TLS13WithSNIAndALPN(t *testing.T) {
	hs := buildHello(helloSpec{
		legacyVersion: 0x0303,
		ciphers:       []uint16{0x1301, 0x1302, 0x1303},
		exts: []extSpec{
			sniExt("ja4.example.com"),
			alpnExt("h2", "http/1.1"),
			supportedVersionsExt(0x0304, 0x0303),
			sigAlgsExt(0x0403, 0x0804),
			groupsExt(0x001d, 0x0017),
		},
	})
	p := parseClientHello(hs)
	if p == nil {
		t.Fatal("parse failed")
	}
	ja4, ja4r, ja4o := ja4FromParsed(p)

	// t + version 13 + SNI 'd' + cipher count 03 + ext count 05 + alpn "h2"
	if !strings.HasPrefix(ja4, "t13d0305h2_") {
		t.Errorf("JA4 head wrong: %s", ja4)
	}
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 must have 3 sections: %s", ja4)
	}
	if len(parts[1]) != 12 || len(parts[2]) != 12 {
		t.Errorf("JA4 hashes must be 12 hex chars: %s", ja4)
	}
	// JA4_r keeps raw values, and SNI/ALPN must be excluded from its ext list.
	if !strings.HasPrefix(ja4r, "t13d0305h2_1301,1302,1303_") {
		t.Errorf("JA4_r ciphers wrong: %s", ja4r)
	}
	if strings.Contains(strings.Split(ja4r, "_")[2], "0000") || strings.Contains(strings.Split(ja4r, "_")[2], "0010") {
		t.Errorf("JA4_r must exclude SNI/ALPN extensions: %s", ja4r)
	}
	// signature algorithms are appended to the extension section.
	if !strings.Contains(ja4r, "0403,0804") {
		t.Errorf("JA4_r must append signature algorithms: %s", ja4r)
	}
	// JA4_o keeps original order and does NOT drop SNI/ALPN.
	if !strings.Contains(strings.Split(ja4o, "_")[2], "0000") {
		t.Errorf("JA4_o must keep SNI in wire order: %s", ja4o)
	}
}

func TestJA4_NoSNIAndNoALPN(t *testing.T) {
	hs := buildHello(helloSpec{
		ciphers: []uint16{0x1301},
		exts:    []extSpec{supportedVersionsExt(0x0304)},
	})
	p := parseClientHello(hs)
	ja4, _, _ := ja4FromParsed(p)
	if !strings.HasPrefix(ja4, "t13i0101") { // 'i' = no SNI, ext count 01, alpn 00
		t.Errorf("JA4 for hello without SNI/ALPN = %s", ja4)
	}
}

func TestJA4_RemovesGreaseButJA3KeepsIt(t *testing.T) {
	greaseCipher := uint16(0x0a0a)
	greaseExt := uint16(0x1a1a)
	hs := buildHello(helloSpec{
		ciphers: []uint16{greaseCipher, 0x1301, 0x1302},
		exts: []extSpec{
			{greaseExt, nil},
			sniExt("grease.example"),
			supportedVersionsExt(0x0304),
		},
	})
	p := parseClientHello(hs)
	if !anyGrease(p.Ciphers) || !anyGrease(p.Extensions) {
		t.Fatal("expected GREASE to be detected")
	}
	ja3, _ := ja3FromParsed(p)
	if !strings.Contains(ja3, "2570") { // 0x0a0a in decimal
		t.Errorf("JA3 must keep GREASE cipher: %s", ja3)
	}
	ja4, ja4r, _ := ja4FromParsed(p)
	if strings.Contains(ja4r, "0a0a") || strings.Contains(ja4r, "1a1a") {
		t.Errorf("JA4_r must not contain GREASE values: %s", ja4r)
	}
	// cipher count excludes GREASE -> 02, extension count excludes GREASE -> 02
	if !strings.HasPrefix(ja4, "t13d0202") {
		t.Errorf("JA4 counts must exclude GREASE: %s", ja4)
	}
}

func TestParseClientHello_ExtensionFields(t *testing.T) {
	hs := buildHello(helloSpec{
		legacyVersion: 0x0303,
		ciphers:       []uint16{0x1301, 0x1302},
		compression:   []byte{0},
		exts: []extSpec{
			sniExt("ext.example"),
			alpnExt("h2", "http/1.1"),
			supportedVersionsExt(0x0304, 0x0303, 0x0302),
			sigAlgsExt(0x0403, 0x0804, 0x0401),
			groupsExt(0x001d, 0x0017, 0x0018),
			keyShareExt(0x001d),
			pointFormatsExt(0, 1),
		},
	})
	p := parseClientHello(hs)
	if p == nil {
		t.Fatal("parseClientHello returned nil")
	}
	if p.LegacyVersion != 0x0303 {
		t.Errorf("legacy version = %#x", p.LegacyVersion)
	}
	if len(p.Ciphers) != 2 || p.Ciphers[0] != 0x1301 {
		t.Errorf("ciphers = %v", p.Ciphers)
	}
	if len(p.Compression) != 1 || p.Compression[0] != 0 {
		t.Errorf("compression = %v", p.Compression)
	}
	if p.SNI != "ext.example" {
		t.Errorf("sni = %q", p.SNI)
	}
	if len(p.ALPN) != 2 || p.ALPN[0] != "h2" || p.ALPN[1] != "http/1.1" {
		t.Errorf("alpn = %v", p.ALPN)
	}
	if len(p.SupportedVersions) != 3 || p.SupportedVersions[0] != 0x0304 {
		t.Errorf("supported versions = %v", p.SupportedVersions)
	}
	if len(p.SignatureAlgorithms) != 3 || p.SignatureAlgorithms[0] != 0x0403 {
		t.Errorf("signature algorithms = %v", p.SignatureAlgorithms)
	}
	if len(p.SupportedGroups) != 3 || len(p.KeyShareGroups) != 1 || p.KeyShareGroups[0] != 0x001d {
		t.Errorf("groups = %v keyshare = %v", p.SupportedGroups, p.KeyShareGroups)
	}
	if len(p.ECPointFormats) != 2 {
		t.Errorf("point formats = %v", p.ECPointFormats)
	}
	if len(p.Extensions) != 7 {
		t.Errorf("extensions = %v", p.Extensions)
	}
}

func TestPopulateClientHelloWith_PopulatesJA4(t *testing.T) {
	hs := buildHello(helloSpec{
		ciphers: []uint16{0x1301},
		exts:    []extSpec{sniExt("populate.example"), supportedVersionsExt(0x0304), alpnExt("h2")},
	})
	info := &ClientHelloInfo{}
	populateClientHelloWith(info, hs)
	if info.JA4 == "" || info.JA4R == "" || info.JA4O == "" {
		t.Errorf("JA4 fields must be populated: %+v", info)
	}
	if info.SNI != "populate.example" || len(info.ALPN) != 1 {
		t.Errorf("parsed fields not copied: %+v", info)
	}
	if len(info.SupportedVersions) != 1 || info.SupportedVersions[0] != 0x0304 {
		t.Errorf("supported versions not copied")
	}
}

// TestPopulateClientHelloWith_PreservesRecordVersion guards the handler path:
// echoHandler sets RecordVersion from the real TLS record, then hands the bare
// handshake payload here. Parsing a bare message carries no record version, so
// it must not clobber the value already set.
func TestPopulateClientHelloWith_PreservesRecordVersion(t *testing.T) {
	hs := buildHello(helloSpec{ciphers: []uint16{0x1301}, exts: []extSpec{sniExt("rv.example")}})

	info := &ClientHelloInfo{RecordVersion: 0x0301}
	populateClientHelloWith(info, hs)
	if info.RecordVersion != 0x0301 {
		t.Errorf("RecordVersion = 0x%04x, want 0x0301 preserved from the record", info.RecordVersion)
	}

	// With the record header included, the parsed version applies as usual.
	info2 := &ClientHelloInfo{}
	populateClientHelloWith(info2, wrapRecords(hs, 0))
	if info2.RecordVersion != 0x0301 {
		t.Errorf("RecordVersion parsed from record = 0x%04x, want 0x0301", info2.RecordVersion)
	}
}

func TestParseClientHello_RejectsGarbage(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, {0x16, 0x03}, {0x99}, bytes.Repeat([]byte{0x01}, 3)} {
		if p := parseClientHello(raw); p != nil {
			t.Errorf("parseClientHello(%x) = %+v, want nil", raw, p)
		}
	}
}
