package main

import (
	"os"
	"strings"
)

// Container health probe: `echo-server healthcheck` exits 0 when this
// deployment answers /health, 1 otherwise.
//
// The image used to probe with `wget http://127.0.0.1:23231/health`, which
// breaks every non-default listener layout: with HTTP_PORT=0 (HTTPS-only, the
// documented way to run without the plain listener) the probe dials a closed
// port and Docker marks the container unhealthy forever; with HTTP_PORT=8080 it
// dials the wrong port. Reading the same environment the server itself reads,
// and trying HTTPS first (the always-on listener) with a plain-HTTP fallback,
// keeps the probe honest for every layout the server supports.
//
// The certificate is self-signed, but the probe only talks to loopback, where
// mcpTLSConfig (see the note there) already skips verification.
func runHealthcheck() {
	os.Exit(healthcheckExitCode())
}

// hasHealthcheckFlag keeps the subcommand in the same argv style as `mcp` and
// `-reset-password`: any of these arguments selects probe mode.
func hasHealthcheckFlag(args []string) bool {
	for _, a := range args {
		if a == "healthcheck" || a == "-healthcheck" || a == "--healthcheck" {
			return true
		}
	}
	return false
}

func healthcheckExitCode() int {
	return healthcheckWithProbe(probeReachable)
}

// healthcheckWithProbe is the decision itself, with the probe injected so tests
// can assert exactly which listeners a deployment's probe dials.
func healthcheckWithProbe(probe func(string) bool) int {
	httpsPort := os.Getenv("PORT")
	if httpsPort == "" {
		httpsPort = defaultHTTPSPort
	}
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = defaultHTTPPort
	}
	if listenerEnabled(httpsPort) && probe("https://127.0.0.1:"+httpsPort) {
		return 0
	}
	if listenerEnabled(httpPort) && probe("http://127.0.0.1:"+httpPort) {
		return 0
	}
	return 1
}

// listenerEnabled mirrors how main() decides whether a listener starts: only
// "0" (or "off", matched case-insensitively) disables one.
func listenerEnabled(port string) bool {
	return port != "0" && !strings.EqualFold(port, "off")
}
