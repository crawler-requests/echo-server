// Package ipclass classifies an IP as datacenter, residential_proxy, or unknown
// from two embedded positive sets. It does no I/O and has no global mutation
// after the range tables are parsed.
//
// A datacenter/hosting hit wins. A residential-proxy hit is a separate positive
// match. Anything else — including a public address that is simply not in the
// datacenter table — is unknown. Missing a datacenter match is not evidence of
// a residential proxy.
package ipclass

import (
	_ "embed"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

//go:embed data/datacenter_ranges.csv
var datacenterCSV []byte

//go:embed data/residential_proxy_ranges.csv
var residentialProxyCSV []byte

var (
	rangesOnce sync.Once
	dcRanges   []net.IPNet
	rpRanges   []net.IPNet
)

// Runtime overrides. The host installs the values produced by its data-source
// providers (embedded defaults are just the lowest-priority provider), so the
// range tables can come from a local directory or a remote cloud library
// without touching this package.
var (
	dcOverride  atomic.Pointer[[]net.IPNet]
	rpOverride  atomic.Pointer[[]net.IPNet]
	orgOverride atomic.Pointer[[]string]
)

// SetDatacenterRanges installs the runtime datacenter prefix set. Passing nil
// restores the embedded table.
func SetDatacenterRanges(nets []net.IPNet) {
	if nets == nil {
		dcOverride.Store(nil)
		return
	}
	cp := append([]net.IPNet(nil), nets...)
	dcOverride.Store(&cp)
}

// SetResidentialRanges installs the runtime residential-proxy prefix set.
// Passing nil restores the embedded table.
func SetResidentialRanges(nets []net.IPNet) {
	if nets == nil {
		rpOverride.Store(nil)
		return
	}
	cp := append([]net.IPNet(nil), nets...)
	rpOverride.Store(&cp)
}

// SetDatacenterOrgKeywords installs the runtime hosting-brand keyword list.
// Passing nil restores the embedded list.
func SetDatacenterOrgKeywords(kw []string) {
	if kw == nil {
		orgOverride.Store(nil)
		return
	}
	cp := append([]string(nil), kw...)
	orgOverride.Store(&cp)
}

// DefaultDatacenterRanges returns the compiled-in datacenter table (ignoring
// runtime overrides). Used to seed the builtin provider at start-up.
func DefaultDatacenterRanges() []net.IPNet {
	initRanges()
	return dcRanges
}

// DefaultResidentialRanges returns the compiled-in residential-proxy table.
func DefaultResidentialRanges() []net.IPNet {
	initRanges()
	return rpRanges
}

// DatacenterRanges returns the effective datacenter set (runtime override or
// the embedded table).
func DatacenterRanges() []net.IPNet {
	if p := dcOverride.Load(); p != nil {
		return *p
	}
	initRanges()
	return dcRanges
}

// ResidentialRanges returns the effective residential-proxy set.
func ResidentialRanges() []net.IPNet {
	if p := rpOverride.Load(); p != nil {
		return *p
	}
	initRanges()
	return rpRanges
}

// DatacenterOrgKeywords returns the effective hosting-brand keyword list.
func DatacenterOrgKeywords() []string {
	if p := orgOverride.Load(); p != nil {
		return *p
	}
	return dcOrgKeywords
}

func initRanges() {
	rangesOnce.Do(func() {
		dcRanges = parseCIDRs(datacenterCSV)
		rpRanges = parseCIDRs(residentialProxyCSV)
	})
}

// parseCIDRs reads one CIDR per line. Blank lines and lines starting with '#'
// are comments. A comma, if present, starts a trailing note and is not part of
// the prefix. This is line-oriented on purpose: encoding/csv treats quotes in
// a comment as syntax and would drop the rest of the file.
func parseCIDRs(raw []byte) []net.IPNet {
	var out []net.IPNet
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		field := line
		if i := strings.IndexByte(field, ','); i >= 0 {
			field = strings.TrimSpace(field[:i])
		}
		field = strings.Trim(field, `"`)
		if _, n, err := net.ParseCIDR(field); err == nil {
			out = append(out, *n)
		}
	}
	return out
}

func inRanges(ip net.IP, ranges []net.IPNet) bool {
	for _, n := range ranges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Classify returns "datacenter", "residential_proxy", or "unknown".
func Classify(ipStr string) string {
	initRanges()
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "unknown"
	}
	// Hosting wins when a prefix is in both sets: a 机房 address stays 机房.
	if inRanges(ip, DatacenterRanges()) {
		return "datacenter"
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return "unknown"
	}
	if inRanges(ip, ResidentialRanges()) {
		return "residential_proxy"
	}
	return "unknown"
}

// dcOrgKeywords are hosting/cloud brand names. They are deliberately narrow:
// matching one of these on an ASN/org name is strong evidence the IP belongs
// to a datacenter, not an eyeball ISP. Generic words like "cloud" are omitted
// to avoid false positives (many consumer ISPs brand products with "cloud").
var dcOrgKeywords = []string{
	"amazon", "aws", "microsoft", "azure", "google", "gcp",
	"digitalocean", "ovh", "hetzner", "linode", "akamai", "cloudflare",
	"fastly", "vultr", "scaleway", "alibaba", "alicloud", "tencent",
	"qcloud", "huawei cloud", "kingsoft", "ucloud", "oracle", "ibm cloud",
	"softlayer", "rackspace", "bytedance", "sakura", "colo", "hosting",
	"datawagon", "leaseweb", "hivelocity", "contabo", "ionos", "gandi",
	"interserver", "servers.com", "ovhcloud", "2cloud", "zenlayer",
}

// OrgLooksDatacenter reports whether an ASN/organization name looks like a
// hosting / cloud provider. It is used as a heuristic tail so cloud IPs whose
// CIDR is not (yet) in the embedded table are still classified datacenter.
func OrgLooksDatacenter(org string) bool {
	o := strings.ToLower(org)
	for _, k := range DatacenterOrgKeywords() {
		if strings.Contains(o, k) {
			return true
		}
	}
	return false
}

// ParseCIDRList parses a CIDR list payload (one prefix per line; blank lines
// and '#' comments ignored; a comma starts a trailing note). Exported so data
// providers decode local/remote tables with exactly the embedded semantics.
func ParseCIDRList(raw []byte) []net.IPNet { return parseCIDRs(raw) }

// ParseKeywordList parses a keyword list (one keyword per line; blank lines
// and '#' comments ignored).
func ParseKeywordList(raw []byte) []string {
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, ','); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		line = strings.ToLower(strings.Trim(line, `"`))
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
