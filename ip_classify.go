package main

import "github.com/crawler-requests/echo-server/ipclass"

// classifyIP is the thin wrapper that the real handler and tests call.
// It delegates to the pure ipclass.Classify for determinism.
func classifyIP(ipStr string) string {
	return ipclass.Classify(ipStr)
}
