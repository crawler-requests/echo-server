package main

import (
	"net/http"
	"strings"
	"time"
)

// buildEchoResponse is the pure, testable core that builds the EchoResponse
// from a request and optional TLS state. It is separated from the HTTP wiring
// so unit tests can call it directly.
func buildEchoResponse(r *http.Request, body []byte, tlsInfo *TLSFingerprint, ipInfo *IPInfo) EchoResponse {
	return EchoResponse{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Method:      r.Method,
		Path:        r.URL.Path,
		HTTPVersion: r.Proto,
		Headers:     r.Header,
		Body:        string(body),
		BodyLength:  len(body),
		TLS:         tlsInfo,
		IP:          ipInfo,
	}
}

// extractClientIP is the same logic used in the handler, extracted for testing
func extractClientIP(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"} {
		if v := r.Header.Get(h); v != "" {
			if idx := strings.Index(v, ","); idx != -1 {
				return strings.TrimSpace(v[:idx])
			}
			return v
		}
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host
}
