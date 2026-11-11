package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// JA4H: the HTTP-client companion to JA4 (FoxIO spec). It fingerprints the
// HTTP layer — method, version, cookie/referer presence, the header name set,
// the Accept-Language, and the cookie field/value sets — and thereby separates
// clients that share a TLS stack. python-requests and curl, for example, can
// hand out the same JA4 when they negotiate the same ALPN, but their header
// sets and cookie handling differ, so their JA4H never does.
//
// Layout: <method><version><cookie><referer><2-digit header count><language>
//         _<12-hex header names>_<12-hex cookie fields>_<12-hex cookie values>
//
// Deviations from the reference implementation, both forced by Go's
// http.Server (the wire is already consumed and re-parsed by net/http):
//
//   - Header *order* is not recoverable (http.Header is a map), so the header
//     name list is sorted before hashing. The reference hashes wire order.
//   - Cookie field names are sorted (the reference does this too), and the
//     value hash uses "name=value" pairs sorted the same way.
//
// Everything else follows the spec: 2-char lowercased method, 2-digit
// version, c/n for cookie and r/n for referer, 2-digit header count, 4-char
// language (dash-stripped, comma-cut, zero padded), and the empty-set markers
// "000000000000".

// ja4hFingerprint computes the JA4H string for a request. Returns "" when the
// request does not carry enough to fingerprint (never for a real HTTP request
// on this server).
func ja4hFingerprint(r *http.Request) string {
	if r == nil {
		return ""
	}
	return ja4hFromParts(r.Method, r.Proto, r.Header)
}

func ja4hFromParts(method, proto string, h http.Header) string {
	m := ja4hMethod(method)
	cookieFlag := "n"
	if len(h.Values("Cookie")) > 0 {
		cookieFlag = "c"
	}
	refererFlag := "n"
	if len(h.Values("Referer")) > 0 {
		refererFlag = "r"
	}

	// Header names: canonicalized by net/http, lowercased here; Cookie and
	// Referer are excluded (they have their own fields).
	names := make([]string, 0, len(h))
	for k := range h {
		lk := strings.ToLower(k)
		if lk == "cookie" || lk == "referer" {
			continue
		}
		if lk == "" || strings.HasPrefix(lk, ":") {
			continue
		}
		names = append(names, lk)
	}
	sort.Strings(names)
	if len(names) > 99 {
		names = names[:99]
	}

	lang := "0000"
	if vals := h.Values("Accept-Language"); len(vals) > 0 {
		lang = ja4hLanguage(vals[0])
	}

	headerHash := ja4hHash12(strings.Join(names, ","))
	fieldHash, valueHash := ja4hCookies(h)

	return m + ja4hVersion(proto) + cookieFlag + refererFlag +
		twoDigits(len(names)) + lang + "_" + headerHash + "_" + fieldHash + "_" + valueHash
}

// ja4hMethod returns the first two letters of the lowercased method.
func ja4hMethod(method string) string {
	m := strings.ToLower(strings.TrimSpace(method))
	if len(m) < 2 {
		return m + strings.Repeat("x", 2-len(m))
	}
	return m[:2]
}

// ja4hVersion maps an HTTP proto to the spec's two digits.
func ja4hVersion(proto string) string {
	switch strings.ToUpper(strings.TrimSpace(proto)) {
	case "HTTP/1.1":
		return "11"
	case "HTTP/1.0":
		return "10"
	case "HTTP/2.0", "HTTP/2":
		return "20"
	case "HTTP/3.0", "HTTP/3":
		return "30"
	}
	// "HTTP/x.y" generic
	if i := strings.LastIndex(proto, "/"); i >= 0 {
		v := strings.ReplaceAll(proto[i+1:], ".", "")
		if len(v) == 2 {
			if _, err := strconv.Atoi(v); err == nil {
				return v
			}
		}
	}
	return "11"
}

// ja4hLanguage keeps 4 characters of the first language tag, dashes removed
// and the quality value cut off, zero padded ("da" → "da00", "en-US" → "enus").
func ja4hLanguage(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, "-", "")
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	if len(v) > 4 {
		v = v[:4]
	}
	return v + strings.Repeat("0", 4-len(v))
}

// ja4hCookies hashes the cookie field names and the name=value pairs. Both are
// sorted by name; pairs missing '=' keep an empty value.
func ja4hCookies(h http.Header) (fields, values string) {
	type kv struct{ name, pair string }
	var pairs []kv
	for _, line := range h.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name := part
			if i := strings.IndexByte(part, '='); i >= 0 {
				name = part[:i]
			}
			pairs = append(pairs, kv{name: strings.TrimSpace(name), pair: part})
		}
	}
	if len(pairs) == 0 {
		return zeroHash(), zeroHash()
	}
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].name < pairs[j].name })
	names := make([]string, len(pairs))
	pvals := make([]string, len(pairs))
	for i, p := range pairs {
		names[i] = p.name
		pvals[i] = p.pair
	}
	return ja4hHash12(strings.Join(names, ",")), ja4hHash12(strings.Join(pvals, ","))
}

// zeroHash is the JA4H marker for an empty set (spec: twelve zeros).
func zeroHash() string { return "000000000000" }

// ja4hHash12 is sha12 without hello_parse.go's empty-string special case: the
// spec always hashes the literal string, and a header name list is never empty
// for a real request.
func ja4hHash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
