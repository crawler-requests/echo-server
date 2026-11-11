package main

import (
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// buildEchoResponse is the pure, testable core that builds the EchoResponse
// from a request and optional TLS state. It is separated from the HTTP wiring
// so unit tests can call it directly.
func buildEchoResponse(r *http.Request, body []byte, tlsInfo *TLSFingerprint, ipInfo *IPInfo) EchoResponse {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return EchoResponse{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Method:      r.Method,
		Scheme:      scheme,
		Host:        r.Host,
		RemoteAddr:  r.RemoteAddr,
		Path:        r.URL.Path,
		Query:       r.URL.RawQuery,
		HTTPVersion: r.Proto,
		Headers:     r.Header,
		Body:        string(body),
		BodyLength:  len(body),
		TLS:         tlsInfo,
		IP:          ipInfo,
	}
}

// extractClientIP is the single client-IP resolution used by the handler.
// Proxy headers win (first XFF hop); otherwise the TCP peer address. IPv6
// literals are handled via SplitHostPort (bare "::1" falls back to itself).
func extractClientIP(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"} {
		if v := r.Header.Get(h); v != "" {
			if idx := strings.Index(v, ","); idx != -1 {
				return strings.TrimSpace(v[:idx])
			}
			return strings.TrimSpace(v)
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// serializeEcho renders the response as JSON (default) or plain text, applying
// an optional dot-path field filter. An empty fieldsSpec means "everything".
//
// Field examples: "ip", "ip.country", "client_hello.sni,ip.latitude".
func serializeEcho(resp EchoResponse, format, fieldsSpec string) ([]byte, string, error) {
	m, err := echoResponseToMap(resp)
	if err != nil {
		return nil, "", err
	}
	if tokens := parseFieldTokens(fieldsSpec); len(tokens) > 0 {
		m = filterFieldsMap(m, tokens)
	}
	if strings.EqualFold(strings.TrimSpace(format), "text") {
		return []byte(mapToText(m)), "text/plain; charset=utf-8", nil
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil, "", err
	}
	return data, "application/json; charset=utf-8", nil
}

// echoResponseToMap converts the response struct into a generic nested map
// using the same JSON tags/omitempty rules as direct JSON output. Round-tripping
// through encoding/json keeps the map and the struct in sync automatically.
func echoResponseToMap(resp EchoResponse) (map[string]any, error) {
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// parseFieldTokens splits a comma-separated fields spec, dropping empties.
func parseFieldTokens(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// filterFieldsMap returns a new map containing only the requested dot paths.
// Unknown paths are silently ignored (lenient: a typo narrows, never errors).
func filterFieldsMap(m map[string]any, fields []string) map[string]any {
	if len(fields) == 0 {
		return m
	}
	out := map[string]any{}
	for _, f := range fields {
		parts := strings.Split(f, ".")
		empty := false
		for _, p := range parts {
			if p == "" {
				empty = true
				break
			}
		}
		if empty {
			continue
		}
		copyPath(m, out, parts)
	}
	return out
}

func copyPath(src, dst map[string]any, parts []string) {
	k := parts[0]
	v, ok := src[k]
	if !ok {
		return
	}
	if len(parts) == 1 {
		dst[k] = v
		return
	}
	child, ok := v.(map[string]any)
	if !ok {
		return
	}
	// Only create the destination branch when the path actually exists,
	// so a typo never leaves an empty object behind.
	if !pathExists(child, parts[1:]) {
		return
	}
	d, ok := dst[k].(map[string]any)
	if !ok {
		d = map[string]any{}
		dst[k] = d
	}
	copyPath(child, d, parts[1:])
}

// pathExists reports whether every segment of parts resolves in m.
func pathExists(m map[string]any, parts []string) bool {
	for i, p := range parts {
		v, ok := m[p]
		if !ok {
			return false
		}
		if i == len(parts)-1 {
			return true
		}
		m, ok = v.(map[string]any)
		if !ok {
			return false
		}
	}
	return false
}

// mapToText flattens a nested map into deterministic "key=value" lines.
// Nested maps use dot paths; strings print verbatim (so bodies stay readable);
// arrays, numbers and booleans print as compact JSON.
func mapToText(m map[string]any) string {
	var sb strings.Builder
	writeText(&sb, "", m)
	return sb.String()
}

func writeText(sb *strings.Builder, prefix string, m map[string]any) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		full := k
		if prefix != "" {
			full = prefix + "." + k
		}
		switch v := m[k].(type) {
		case map[string]any:
			writeText(sb, full, v)
		case nil:
			sb.WriteString(full + "=\n")
		case string:
			sb.WriteString(full + "=" + v + "\n")
		default:
			b, err := json.Marshal(v)
			if err != nil {
				continue
			}
			sb.WriteString(full + "=" + string(b) + "\n")
		}
	}
}
