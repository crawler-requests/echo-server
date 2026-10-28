package main

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
	dcRanges []net.IPNet // parsed CIDRs for datacenter ranges
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

// classifyIP returns datacenter | residential | proxy | unknown based on embedded ranges.
// For the scope of this goal a minimal datacenter list is shipped; residential/proxy are best-effort via heuristics.
func classifyIP(ipStr string) string {
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
	// Heuristic: private / loopback ranges are not residential either
	if ip.IsLoopback() || ip.IsPrivate() {
		return "unknown"
	}
	// Default to residential when no datacenter match (real residential proxy detection would need larger commercial lists)
	return "residential"
}
