// Package safeurl decides whether an operator-supplied URL may be fetched.
//
// The IP-intelligence chain and the dataset engine both accept a URL from an
// admin and then request it from the server. Without a check that is a
// server-side request forgery primitive: a URL pointing at 127.0.0.1,
// 169.254.169.254 (cloud metadata) or an RFC 1918 address makes the server
// probe its own network on the caller's behalf. This package is the single
// place that answers "is this target allowed", so the two engines cannot drift.
//
// Policy:
//   - only http and https schemes,
//   - the host must resolve, and every resolved address must be public,
//   - loopback, private, link-local (including 169.254.169.254), unique-local,
//     multicast and unspecified addresses are refused,
//   - hostnames that resolve to a blocked address are refused too, so a DNS
//     record cannot smuggle the request into the internal network,
//   - a redirect to a blocked target is refused at dial time (the Redirect
//     helper re-checks each hop).
//
// Resolve happens at dial time as well as at submit time: a name that pointed
// at a public address when the config was saved could be re-pointed later, so
// the check must run on the actual connection, not only on the string.
package safeurl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// ErrBlocked is returned when a target is not allowed.
var ErrBlocked = errors.New("target address is not allowed")

// allowPrivate is a process-local override for tests. It is deliberately a
// package variable rather than an environment setting: production builds must
// not be able to turn the SSRF guard off from configuration, or the guard just
// becomes a suggestion.
var allowPrivate atomic.Bool

// AllowPrivateForTests disables the private-address check for this process.
// Tests that stand up an httptest server on 127.0.0.1 need it; nothing in a
// deployed binary calls it.
func AllowPrivateForTests(allow bool) { allowPrivate.Store(allow) }

// blockedCIDRs covers ranges that are never a legitimate public API endpoint.
var blockedCIDRs = func() []*net.IPNet {
	var out []*net.IPNet
	for _, s := range []string{
		"0.0.0.0/8",      // "this network"
		"10.0.0.0/8",     // RFC 1918
		"100.64.0.0/10",  // carrier-grade NAT
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local, incl. cloud metadata 169.254.169.254
		"172.16.0.0/12",  // RFC 1918
		"192.0.0.0/24",   // IETF protocol assignments
		"192.168.0.0/16", // RFC 1918
		"198.18.0.0/15",  // benchmarking
		"224.0.0.0/4",    // multicast
		"240.0.0.0/4",    // reserved
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
		"ff00::/8",       // IPv6 multicast
		"::/128",         // unspecified
		"64:ff9b::/96",   // NAT64 (can map to private v4)
	} {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// BlockedIP reports whether ip must not be contacted.
func BlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if allowPrivate.Load() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// NAT64 / IPv4-mapped: check the embedded v4 address as well.
	if v4 := ip.To4(); v4 != nil {
		for _, n := range blockedCIDRs {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	for _, n := range blockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateURL checks the scheme and the literal host (no DNS lookup). It is the
// cheap check that runs when configuration is saved.
func ValidateURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q is not allowed (use http or https)", ErrBlocked, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("url has no host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if BlockedIP(ip) {
			return fmt.Errorf("%w: %s is a loopback/private/link-local address", ErrBlocked, host)
		}
		return nil
	}
	// A bare label on a public host name is fine; it is resolved at dial time.
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return fmt.Errorf("%w: %s resolves to loopback", ErrBlocked, host)
	}
	return nil
}

// ResolvePublic resolves a hostname and insists that every address is public.
func ResolvePublic(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if BlockedIP(ip) {
			return fmt.Errorf("%w: %s", ErrBlocked, host)
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("cannot resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("cannot resolve %s: no addresses", host)
	}
	for _, a := range addrs {
		if BlockedIP(a.IP) {
			return fmt.Errorf("%w: %s resolves to %s", ErrBlocked, host, a.IP)
		}
	}
	return nil
}

// SafeDialer returns a DialContext that refuses to connect to a blocked address.
// Using it closes the DNS-rebinding gap: the check runs on the address actually
// dialled, not on the name that was validated earlier.
func SafeDialer(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip := net.ParseIP(host); ip != nil {
			if BlockedIP(ip) {
				return nil, fmt.Errorf("%w: refusing to dial %s", ErrBlocked, host)
			}
			return d.DialContext(ctx, network, addr)
		}
		// Resolve ourselves so the resolved addresses can be vetted before any
		// connection is made.
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, a := range addrs {
			if BlockedIP(a.IP) {
				return nil, fmt.Errorf("%w: %s resolves to %s", ErrBlocked, host, a.IP)
			}
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = errors.New("no address to dial")
		}
		return nil, lastErr
	}
}

// CheckRedirect refuses a redirect whose target is blocked, so a public URL
// cannot bounce the request into the internal network.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("stopped after 5 redirects")
	}
	return ValidateURL(req.URL.String())
}

// Client builds an http.Client wired with the safe dialer and redirect check.
func Client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     &http.Transport{DialContext: SafeDialer(timeout)},
		CheckRedirect: CheckRedirect,
	}
}

// Allowed reports whether a URL may be fetched, resolving the host too. It is
// the thorough check used at configuration-save time so the operator gets the
// error immediately instead of at the next refresh.
func Allowed(raw string, timeout time.Duration) error {
	if err := ValidateURL(raw); err != nil {
		return err
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return ResolvePublic(ctx, u.Hostname())
}
