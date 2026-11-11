package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"strings"
)

// TLS extension types referenced while parsing a ClientHello.
const (
	extServerName           = 0x0000
	extSupportedGroups      = 0x000a
	extECPointFormats       = 0x000b
	extSignatureAlgorithms  = 0x000d
	extALPN                 = 0x0010
	extSupportedVersions    = 0x002b
	extKeyShare             = 0x0033
	extEncryptedClientHello = 0xfe0d
)

// clientHelloParsed is the fully parsed view of a ClientHello used for
// fingerprinting and echoing.
type clientHelloParsed struct {
	RecordVersion       uint16
	LegacyVersion       uint16
	Ciphers             []uint16
	Compression         []byte
	Extensions          []uint16 // wire order, GREASE included
	SNI                 string
	ALPN                []string
	SupportedVersions   []uint16
	SignatureAlgorithms []uint16
	SupportedGroups     []uint16 // JA3 "elliptic curves"
	KeyShareGroups      []uint16
	ECPointFormats      []byte
	HasECH              bool
}

// grease reports whether a TLS identifier is a GREASE value (0x?a?a with
// matching bytes), which browsers insert to keep parsers honest. JA4 removes
// them; JA3 keeps them (that is why GREASE changes a JA3).
func grease(v uint16) bool {
	return v>>8 == v&0xff && v&0x0f == 0x0a
}

// handshakeFromRaw normalizes input that may be a bare handshake message or
// one or more complete TLS records, returning the reassembled handshake byte
// stream.
func handshakeFromRaw(raw []byte) []byte {
	if len(raw) == 0 {
		return nil
	}
	if raw[0] != 0x16 {
		return raw
	}
	var hs []byte
	off := 0
	for off+5 <= len(raw) && raw[off] == 0x16 {
		n := int(raw[off+3])<<8 | int(raw[off+4])
		off += 5
		if off+n > len(raw) {
			n = len(raw) - off
		}
		hs = append(hs, raw[off:off+n]...)
		off += n
	}
	return hs
}

// byteReader is a bounds-checked cursor over TLS wire data.
type byteReader struct {
	b   []byte
	off int
}

func (r *byteReader) remaining() int { return len(r.b) - r.off }

func (r *byteReader) u8() (uint8, bool) {
	if r.remaining() < 1 {
		return 0, false
	}
	v := r.b[r.off]
	r.off++
	return v, true
}

func (r *byteReader) u16() (uint16, bool) {
	if r.remaining() < 2 {
		return 0, false
	}
	v := uint16(r.b[r.off])<<8 | uint16(r.b[r.off+1])
	r.off += 2
	return v, true
}

func (r *byteReader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.remaining() < n {
		return nil, false
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v, true
}

func (r *byteReader) u16list(nBytes int) []uint16 {
	raw, ok := r.bytes(nBytes)
	if !ok {
		return nil
	}
	out := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		out = append(out, uint16(raw[i])<<8|uint16(raw[i+1]))
	}
	return out
}

// parseClientHello parses a ClientHello (bare message or TLS record(s)).
// Truncated or malformed input yields whatever was decoded so far; the caller
// can treat empty slices as "not present".
func parseClientHello(raw []byte) *clientHelloParsed {
	hs := handshakeFromRaw(raw)
	if len(hs) < 10 || hs[0] != 0x01 {
		return nil
	}
	msgLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+msgLen > len(hs) {
		return nil // incomplete handshake message
	}
	p := &clientHelloParsed{}
	if raw[0] == 0x16 && len(raw) >= 5 {
		p.RecordVersion = uint16(raw[1])<<8 | uint16(raw[2])
	}

	r := &byteReader{b: hs[4 : 4+msgLen]}
	legacy, ok := r.u16()
	if !ok {
		return nil
	}
	p.LegacyVersion = legacy
	if _, ok := r.bytes(32); !ok { // random
		return p
	}
	sessLen, ok := r.u8()
	if !ok {
		return p
	}
	if _, ok := r.bytes(int(sessLen)); !ok {
		return p
	}
	csLen, ok := r.u16()
	if !ok {
		return p
	}
	p.Ciphers = r.u16list(int(csLen))
	compLen, ok := r.u8()
	if !ok {
		return p
	}
	comp, ok := r.bytes(int(compLen))
	if !ok {
		return p
	}
	p.Compression = append([]byte(nil), comp...)

	extTotal, ok := r.u16()
	if !ok {
		return p // TLS 1.0/1.1 style hello with no extensions
	}
	extBytes, ok := r.bytes(int(extTotal))
	if !ok {
		extBytes = r.b[r.off:]
	}
	exts := &byteReader{b: extBytes}
	for exts.remaining() >= 4 {
		typ, _ := exts.u16()
		l, _ := exts.u16()
		data, ok := exts.bytes(int(l))
		if !ok {
			break
		}
		p.Extensions = append(p.Extensions, typ)
		switch typ {
		case extServerName:
			if name := parseSNI(data); name != "" && p.SNI == "" {
				p.SNI = name
			}
		case extALPN:
			p.ALPN = parseALPN(data)
		case extSupportedVersions:
			// ClientHello form: 1-byte list length + 2-byte versions
			if len(data) >= 1 {
				n := int(data[0])
				if n > len(data)-1 {
					n = len(data) - 1
				}
				p.SupportedVersions = (&byteReader{b: data[1 : 1+n]}).u16list(n)
			}
		case extSignatureAlgorithms:
			// 2-byte list length + 2-byte algorithms
			if len(data) >= 2 {
				n := int(data[0])<<8 | int(data[1])
				if n > len(data)-2 {
					n = len(data) - 2
				}
				p.SignatureAlgorithms = (&byteReader{b: data[2 : 2+n]}).u16list(n)
			}
		case extSupportedGroups:
			if len(data) >= 2 {
				n := int(data[0])<<8 | int(data[1])
				if n > len(data)-2 {
					n = len(data) - 2
				}
				p.SupportedGroups = (&byteReader{b: data[2 : 2+n]}).u16list(n)
			}
		case extKeyShare:
			if len(data) >= 2 {
				n := int(data[0])<<8 | int(data[1])
				if n > len(data)-2 {
					n = len(data) - 2
				}
				ks := &byteReader{b: data[2 : 2+n]}
				for ks.remaining() >= 4 {
					group, _ := ks.u16()
					kl, _ := ks.u16()
					if _, ok := ks.bytes(int(kl)); !ok {
						break
					}
					p.KeyShareGroups = append(p.KeyShareGroups, group)
				}
			}
		case extECPointFormats:
			if len(data) >= 1 {
				n := int(data[0])
				if n > len(data)-1 {
					n = len(data) - 1
				}
				p.ECPointFormats = append([]byte(nil), data[1:1+n]...)
			}
		case extEncryptedClientHello:
			p.HasECH = true
		}
	}
	return p
}

// parseSNI extracts the hostname from a server_name extension payload.
func parseSNI(ext []byte) string {
	r := &byteReader{b: ext}
	listLen, ok := r.u16()
	if !ok {
		return ""
	}
	list, ok := r.bytes(int(listLen))
	if !ok {
		return ""
	}
	lr := &byteReader{b: list}
	for lr.remaining() >= 3 {
		nameType, _ := lr.u8()
		nameLen, _ := lr.u16()
		name, ok := lr.bytes(int(nameLen))
		if !ok {
			return ""
		}
		if nameType == 0 { // host_name
			return string(name)
		}
	}
	return ""
}

// parseALPN extracts the protocol list from an ALPN extension payload.
func parseALPN(ext []byte) []string {
	r := &byteReader{b: ext}
	listLen, ok := r.u16()
	if !ok {
		return nil
	}
	list, ok := r.bytes(int(listLen))
	if !ok {
		list = ext[2:]
	}
	lr := &byteReader{b: list}
	var out []string
	for lr.remaining() >= 1 {
		n, _ := lr.u8()
		proto, ok := lr.bytes(int(n))
		if !ok {
			break
		}
		out = append(out, string(proto))
	}
	return out
}

// populateClientHello fills ClientHelloInfo from the fallback global captured
// bytes (used by tests and legacy callers).
func populateClientHello(info *ClientHelloInfo) {
	populateClientHelloWith(info, getCapturedClientHello())
}

// populateClientHelloWith fills ClientHelloInfo from explicit raw ClientHello
// bytes (bare handshake message or TLS record(s)) and computes JA3/JA4.
func populateClientHelloWith(info *ClientHelloInfo, raw []byte) {
	if info == nil || len(raw) == 0 {
		return
	}
	info.Raw = base64.StdEncoding.EncodeToString(raw)
	info.RawHex = hexEncode(raw)
	info.Length = len(raw)

	p := parseClientHello(raw)
	if p == nil {
		return
	}
	// RecordVersion only comes from the TLS record header (a bare handshake
	// message carries none). Keep a value the caller already set from the
	// actual records instead of clobbering it with 0.
	if p.RecordVersion != 0 {
		info.RecordVersion = p.RecordVersion
	}
	info.Version = p.LegacyVersion
	info.CipherSuites = p.Ciphers
	info.Extensions = p.Extensions
	info.CompressionMethods = p.Compression
	if info.SNI == "" {
		info.SNI = p.SNI
	}
	info.ALPN = p.ALPN
	info.SupportedVersions = p.SupportedVersions
	info.SignatureAlgorithms = p.SignatureAlgorithms
	info.SupportedGroups = p.SupportedGroups
	info.KeyShareGroups = p.KeyShareGroups
	info.HasECH = p.HasECH
	info.HasGREASE = anyGrease(p.Ciphers) || anyGrease(p.Extensions)

	info.JA3, info.JA3Hash = ja3FromParsed(p)
	info.JA4, info.JA4R, info.JA4O = ja4FromParsed(p)
}

func anyGrease(vs []uint16) bool {
	for _, v := range vs {
		if grease(v) {
			return true
		}
	}
	return false
}

// computeJA3 returns the JA3 string and its fingerprint hash for raw bytes.
func computeJA3(raw []byte) (string, string) {
	p := parseClientHello(raw)
	if p == nil {
		return "", ""
	}
	return ja3FromParsed(p)
}

// ja3FromParsed builds "SSLVersion,CipherSuites,Extensions,Curves,PointFormats"
// (wire order, GREASE included) and its MD5 digest. The MD5 is the industry
// definition of a JA3 hash — fingerprint databases compare against it, so it
// must be a real MD5 rather than a stand-in.
func ja3FromParsed(p *clientHelloParsed) (string, string) {
	s := strings.Join([]string{
		uint16Dec(p.LegacyVersion),
		joinUint16(p.Ciphers),
		joinUint16(p.Extensions),
		joinUint16(p.SupportedGroups),
		joinBytes(p.ECPointFormats),
	}, ",")
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:])
}

// ja4FromParsed builds JA4 (sorted, hashed), JA4_r (sorted, raw values) and
// JA4_o (original order, raw values) following the FoxIO JA4 specification.
func ja4FromParsed(p *clientHelloParsed) (ja4, ja4r, ja4o string) {
	version := p.LegacyVersion
	for _, v := range p.SupportedVersions {
		if !grease(v) && v > version {
			version = v
		}
	}
	sniFlag := "i"
	if p.SNI != "" {
		sniFlag = "d"
	}
	ciphersNonGrease := filterGreaseStrings(p.Ciphers)
	extsNonGrease := filterGreaseStrings(p.Extensions)
	alpnFlag := alpnPair(p.ALPN)

	cipherCount := len(ciphersNonGrease)
	if cipherCount > 99 {
		cipherCount = 99
	}
	extCount := len(extsNonGrease)
	if extCount > 99 {
		extCount = 99
	}
	head := "t" + ja4Version(version) + sniFlag +
		twoDigits(cipherCount) + twoDigits(extCount) + alpnFlag

	// Ciphers: sorted for JA4/JA4_r, wire order for JA4_o.
	sortedCiphers := append([]string(nil), ciphersNonGrease...)
	sort.Strings(sortedCiphers)
	origCiphers := ciphersNonGrease

	// Extensions: sorted and with SNI/ALPN removed for JA4/JA4_r; wire order
	// and unfiltered for JA4_o (this mirrors the reference implementation).
	sortedExts := make([]string, 0, len(extsNonGrease))
	for _, e := range extsNonGrease {
		if e == "0000" || e == "0010" {
			continue
		}
		sortedExts = append(sortedExts, e)
	}
	sort.Strings(sortedExts)
	origExts := extsNonGrease

	sigAlgs := filterGreaseStrings(p.SignatureAlgorithms)
	sigSuffix := ""
	if len(sigAlgs) > 0 {
		sigSuffix = "_" + strings.Join(sigAlgs, ",")
	}

	sortedExtStr := strings.Join(sortedExts, ",") + sigSuffix
	origExtStr := strings.Join(origExts, ",") + sigSuffix

	cipherHash := orZero(sha12(strings.Join(sortedCiphers, ",")))
	extHash := orZero(sha12(sortedExtStr))
	ja4 = head + "_" + cipherHash + "_" + extHash

	ja4r = head + "_" + orZero(strings.Join(sortedCiphers, ",")) + "_" + orZero(sortedExtStr)
	ja4o = head + "_" + orZero(strings.Join(origCiphers, ",")) + "_" + orZero(origExtStr)
	return ja4, ja4r, ja4o
}

// filterGreaseStrings renders identifiers as 4-char lowercase hex, dropping
// GREASE values.
func filterGreaseStrings(vs []uint16) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if grease(v) {
			continue
		}
		out = append(out, fourHex(v))
	}
	return out
}

func fourHex(v uint16) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[v>>12], digits[(v>>8)&0xf], digits[(v>>4)&0xf], digits[v&0xf]})
}

func twoDigits(n int) string {
	if n > 99 {
		n = 99
	}
	return string([]byte{byte('0' + n/10), byte('0' + n%10)})
}

func uint16Dec(v uint16) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v%10]
		v /= 10
	}
	return string(b[i:])
}

// ja4Version maps the negotiated TLS version to the two-character JA4 code.
func ja4Version(v uint16) string {
	switch v {
	case 0x0002:
		return "s2"
	case 0x0300:
		return "s3"
	case 0x0301:
		return "10"
	case 0x0302:
		return "11"
	case 0x0303:
		return "12"
	case 0x0304:
		return "13"
	}
	return "00"
}

// alpnPair returns the first and last character of the first ALPN protocol,
// or "00" when none was offered.
func alpnPair(alpns []string) string {
	if len(alpns) == 0 || alpns[0] == "" {
		return "00"
	}
	a := alpns[0]
	first, last := a[0], a[len(a)-1]
	if first >= 0x80 {
		first = '9'
	}
	if last >= 0x80 {
		last = '9'
	}
	return string([]byte{first, last})
}

func sha12(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func orZero(s string) string {
	if s == "" {
		return "000000000000"
	}
	return s
}

// parseClientHelloFields is kept for callers/tests that only need the core
// fields. It returns (legacy version, cipher suites, extension types, SNI).
func parseClientHelloFields(raw []byte) (uint16, []uint16, []uint16, string) {
	p := parseClientHello(raw)
	if p == nil {
		return 0, nil, nil, ""
	}
	return p.LegacyVersion, p.Ciphers, p.Extensions, p.SNI
}

func joinUint16(v []uint16) string {
	if len(v) == 0 {
		return ""
	}
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = uint16Dec(x)
	}
	return strings.Join(s, "-")
}

func joinBytes(v []byte) string {
	if len(v) == 0 {
		return ""
	}
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = uint16Dec(uint16(x))
	}
	return strings.Join(s, "-")
}

func hexEncode(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexChars[c>>4]
		out[i*2+1] = hexChars[c&0x0f]
	}
	return string(out)
}
