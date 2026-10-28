// Package ipclass provides pure, deterministic IP classification (datacenter/residential/proxy/unknown)
// based on an embedded range table. It has no I/O or global state.
package ipclass

import (
	_ "embed"
	"encoding/csv"
	"net"
	"strings"
	"sync"
)

//go:embed data/datacenter_ranges.csv
var datacenterCSV []byte

var (
	dcOnce   sync.Once
	dcRanges []net.IPNet
)

func initDatacenterRanges() {
	dcOnce.Do(func() {
		if len(datacenterCSV) == 0 {
			return
		}
		r := csv.NewReader(strings.NewReader(string(datacenterCSV)))
		records, _ := r.ReadAll()
		for _, rec := range records {
			if len(rec) == 0 {
				continue
			}
			cidr := strings.TrimSpace(rec[0])
			if _, n, err := net.ParseCIDR(cidr); err == nil {
				dcRanges = append(dcRanges, *n)
			}
		}
	})
}

// Classify returns "datacenter" | "residential" | "proxy" | "unknown" for the given IP string.
// It is a pure function with no side effects.
func Classify(ipStr string) string {
	initDatacenterRanges()
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "unknown"
	}
	for _, n := range dcRanges {
		if n.Contains(ip) {
			return "datacenter"
		}
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return "unknown"
	}
	return "residential"
}
