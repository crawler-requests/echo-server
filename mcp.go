package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// MCP server: exposes this deployment's capabilities to AI agents.
//
// Agents increasingly cannot use a REST API by reading docs — they need a
// machine-readable contract they can call directly. This is a Model Context
// Protocol server over stdio (the transport Claude Code, Codex and most MCP
// clients use), so an agent can add it as a tool and immediately:
//
//   - check its own egress IP (the /ip fast path),
//   - identify itself from the TLS/HTTP2 fingerprint (curl vs a spoofed Chrome),
//   - look up any address's geo/ASN/connection type,
//   - read the query log, stats and provider health,
//   - issue a one-time password reset token for a locked-out account.
//
// Design choices:
//   - No MCP SDK dependency: the protocol is JSON-RPC 2.0 over newline-delimited
//     JSON on stdin/stdout, which is small enough to implement exactly.
//   - It is a *client* of the running server, not a second server: every tool
//     calls the same authenticated HTTP API, so permissions, auditing, rate
//     limits and the query log all apply unchanged.
//   - Auto-discovery of the endpoint: ECHO_SERVER_URL, else https://127.0.0.1:23232
//     falling back to http://127.0.0.1:23231.
//   - Credentials: ECHO_SERVER_API_KEY (preferred, revocable) or
//     ECHO_SERVER_TOKEN (a JWT). Tools that mutate require an admin-scoped key
//     and fail with a clear message otherwise.

// mcpServerVersion is advertised in initialize.
const mcpServerVersion = "1.0.0"

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// mcpTool is one advertised tool.
type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	// adminOnly tools need an admin-scoped credential; the description says so
	// and the handler refuses with a helpful error rather than a bare 403.
	adminOnly bool
	Handler   func(args map[string]any) (any, error)
}

// hasMCPFlag reports whether the process should run as an MCP server.
func hasMCPFlag(args []string) bool {
	for _, a := range args {
		if a == "mcp" || a == "-mcp" || a == "--mcp" {
			return true
		}
	}
	return false
}

// runMCPServer is the entry point from main().
func runMCPServer() {
	// MCP conversations are on stdout; any log line must go to stderr or it
	// corrupts the JSON stream.
	logf := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	}

	cli := newMCPClient()
	srv := &mcpRuntime{cli: cli, logf: logf}

	dec := json.NewDecoder(bufio.NewReaderSize(os.Stdin, 1<<20))
	enc := json.NewEncoder(os.Stdout)
	for {
		var req mcpRequest
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			logf("mcp: bad request: %v", err)
			continue
		}
		if req.JSONRPC == "" {
			req.JSONRPC = "2.0"
		}
		resp := srv.handle(req)
		if resp == nil {
			continue // notification: no response by design
		}
		if err := enc.Encode(resp); err != nil {
			logf("mcp: write failed: %v", err)
			return
		}
	}
}

// mcpRuntime ties the protocol to the HTTP client.
type mcpRuntime struct {
	cli  *mcpClient
	logf func(string, ...any)
}

// ListTools is the catalogue, in the order an agent should try them.
func (r *mcpRuntime) tools() []mcpTool {
	return []mcpTool{
		{
			Name:        "echo_server_health",
			Description: "Check that the echo server is reachable and report its version, ports and uptime. Call this first.",
			InputSchema: objSchema(nil, nil),
			Handler:     func(map[string]any) (any, error) { return r.cli.get("/health") },
		},
		{
			Name:        "echo_server_my_ip",
			Description: "Return the egress IP the echo server sees for THIS agent's requests (the fast /ip endpoint). Use it to confirm a proxy or crawler exit node.",
			InputSchema: objSchema(nil, nil),
			Handler: func(map[string]any) (any, error) {
				body, err := r.cli.getRaw("/ip?format=text")
				if err != nil {
					return nil, err
				}
				return map[string]any{"ip": strings.TrimSpace(string(body))}, nil
			},
		},
		{
			Name:        "echo_server_self_fingerprint",
			Description: "Send a request through /echo and report how the server identifies THIS agent: client name/family, JA3/JA4, HTTP/2 fingerprint, and whether the User-Agent is spoofed. Use it to verify that an impersonation setup actually looks like the browser it claims.",
			InputSchema: objSchema(map[string]any{
				"user_agent": strSchema("Optional User-Agent header to send (to test spoofing)."),
			}, nil),
			Handler: r.selfFingerprint,
		},
		{
			Name:        "echo_server_lookup_ip",
			Description: "Look up an arbitrary IP address: country, region, city, coordinates, ASN/org, and connection type (datacenter / residential_proxy / unknown). Up to 100 addresses per call.",
			InputSchema: objSchema(map[string]any{
				"ips":     strListSchema("One or more IP addresses (IPv4/IPv6 literals)."),
				"nocache": boolSchema("Bypass the 24h result cache to force a fresh provider query."),
			}, []string{"ips"}),
			Handler: r.lookupIPs,
		},
		{
			Name:        "echo_server_search_ja4",
			Description: "Search the built-in JA4 fingerprint library by fingerprint prefix or by client name/family (e.g. 'chrome', 'curl', 'cobalt'). Returns the matched client, confidence and how many real-world observations back it.",
			InputSchema: objSchema(map[string]any{
				"query": strSchema("Fingerprint substring or client name/family; empty returns the most common fingerprints."),
				"limit": numSchema("Max results (default 20, max 200)."),
			}, nil),
			Handler: r.searchJA4,
		},
		{
			Name:        "echo_server_query_log",
			Description: "Read recent /echo requests. Filter by client name, client family, spoofed state, connection type, country, IP or free text. This is how you audit what traffic actually reached this deployment.",
			InputSchema: objSchema(map[string]any{
				"limit":   numSchema("Max rows (default 50, max 2000)."),
				"ip":      strSchema("Exact source IP."),
				"client":  strSchema("Client name, e.g. curl, Chrome, python-requests."),
				"family":  strSchema("browser | cli | library | runtime | tool | bot | malware | tunnel."),
				"spoofed": boolSchema("true only requests where the UA disagreed with the TLS fingerprint."),
				"type":    strSchema("Connection type: datacenter | residential_proxy | unknown."),
				"country": strSchema("Country name, e.g. Japan."),
				"days":    numSchema("Only rows newer than N days."),
			}, nil),
			Handler: r.queryLog,
		},
		{
			Name:        "echo_server_stats",
			Description: "Traffic summary for the last N hours: total requests, unique IPs, top clients/families/countries/ASNs, and how many requests had a spoofed User-Agent or an unidentified client.",
			InputSchema: objSchema(map[string]any{
				"hours": numSchema("Window length in hours (default 24, max 720)."),
			}, nil),
			Handler: r.stats,
		},
		{
			Name:        "echo_server_providers",
			Description: "IP-intelligence provider chain: per-provider priority, enabled state, call/success counts and average latency, so you can tell which upstream is degrading.",
			InputSchema: objSchema(nil, nil),
			Handler:     func(map[string]any) (any, error) { return r.cli.get("/api/ipproviders") },
		},
		{
			Name:        "echo_server_issue_password_reset",
			Description: "Issue a one-time password-reset token for an account (admin credential required). The token is shown once, expires in 30 minutes and works exactly once; hand it to the user, who redeems it at /ui/ under \"Forgot password?\".",
			InputSchema: objSchema(map[string]any{
				"username": strSchema("Account to issue the token for."),
			}, []string{"username"}),
			adminOnly: true,
			Handler:   r.issuePasswordReset,
		},
	}
}

func (r *mcpRuntime) handle(req mcpRequest) *mcpResponse {
	reply := func(result any) *mcpResponse {
		return &mcpResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
	}
	fail := func(code int, msg string) *mcpResponse {
		return &mcpResponse{JSONRPC: "2.0", ID: req.ID, Error: &mcpError{Code: code, Message: msg}}
	}

	switch req.Method {
	case "initialize":
		return reply(map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{
				"name":    "echo-server",
				"version": mcpServerVersion,
			},
			"instructions": r.accessInstructions(),
		})
	case "notifications/initialized", "notifications/cancelled":
		return nil // notifications get no reply
	case "ping":
		return reply(map[string]any{})
	case "tools/list":
		list := make([]map[string]any, 0, len(r.tools()))
		for _, t := range r.tools() {
			list = append(list, map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"inputSchema": t.InputSchema,
			})
		}
		return reply(map[string]any{"tools": list})
	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return fail(-32602, "invalid params: "+err.Error())
		}
		tool, ok := r.findTool(params.Name)
		if !ok {
			return fail(-32602, "unknown tool: "+params.Name)
		}
		if tool.adminOnly && !r.cli.isAdmin() {
			return reply(mcpToolResult(fmt.Sprintf(
				"%q requires an admin-scoped credential (ECHO_SERVER_API_KEY with scope=admin, or an admin JWT in ECHO_SERVER_TOKEN). Current credential is absent or viewer-scoped.",
				tool.Name), true))
		}
		out, err := tool.Handler(params.Arguments)
		if err != nil {
			// Tool failures are reported in-band (isError) so the agent sees
			// the message as data instead of a protocol fault it cannot read.
			return reply(mcpToolResult(err.Error(), true))
		}
		enc, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return reply(mcpToolResult(err.Error(), true))
		}
		return reply(mcpToolResult(string(enc), false))
	default:
		return fail(-32601, "method not found: "+req.Method)
	}
}

// accessInstructions tells the agent, up front, whether anything is missing.
// An agent that hits a 401 mid-task and has to guess is worse than one that
// was told at handshake time.
func (r *mcpRuntime) accessInstructions() string {
	switch {
	case r.cli.admin:
		return "Connected with an admin credential: every tool, including password-reset issuance, is available."
	case r.cli.key != "" || r.cli.token != "":
		return "Connected with a non-admin credential: read-only tools work; echo_server_issue_password_reset is refused. " +
			"Use an admin-scoped API key or admin JWT to unlock it."
	default:
		return "No credential configured. If the server's agent_access policy is not public, requests fail with 401/403. " +
			"Set ECHO_SERVER_API_KEY (or ECHO_SERVER_TOKEN) before starting the MCP server."
	}
}

func (r *mcpRuntime) findTool(name string) (mcpTool, bool) {
	for _, t := range r.tools() {
		if t.Name == name {
			return t, true
		}
	}
	return mcpTool{}, false
}

// mcpToolResult wraps a tool's output in the MCP content envelope.
func mcpToolResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

// --------------------------------------------------------------------------
// Tool implementations

func (r *mcpRuntime) selfFingerprint(args map[string]any) (any, error) {
	ua, _ := args["user_agent"].(string)
	req, err := r.cli.newRequest("/echo?fields=client,ja3,ja4,ja3_hash,http2,tls,ip.country,ip.asn,ip.connection_type")
	if err != nil {
		return nil, err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	var out map[string]any
	if err := r.cli.do(req, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *mcpRuntime) lookupIPs(args map[string]any) (any, error) {
	ips := toStringList(args["ips"])
	if len(ips) == 0 {
		return nil, errors.New("ips is required: pass one or more IP literals")
	}
	if len(ips) > 100 {
		return nil, errors.New("at most 100 addresses per call")
	}
	body := map[string]any{"ips": ips}
	if nocache, _ := args["nocache"].(bool); nocache {
		body["nocache"] = true
	}
	var out map[string]any
	if err := r.cli.post("/api/ip/lookup", body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *mcpRuntime) searchJA4(args map[string]any) (any, error) {
	q := strings.TrimSpace(fmt.Sprint(args["query"]))
	limit := intFrom(args["limit"], 20, 1, 200)
	u := "/api/ja4/search?limit=" + itoa(limit)
	if q != "" {
		u += "&q=" + url.QueryEscape(q)
	}
	return r.cli.get(u)
}

func (r *mcpRuntime) queryLog(args map[string]any) (any, error) {
	q := url.Values{}
	q.Set("limit", itoa(intFrom(args["limit"], 50, 1, 2000)))
	for _, k := range []string{"ip", "client", "family", "type", "country"} {
		if v := strings.TrimSpace(fmt.Sprint(args[k])); v != "" && v != "<nil>" {
			q.Set(k, v)
		}
	}
	if days := intFrom(args["days"], 0, 0, 3650); days > 0 {
		q.Set("days", itoa(days))
	}
	if sp, ok := args["spoofed"].(bool); ok {
		if sp {
			q.Set("spoofed", "1")
		} else {
			q.Set("spoofed", "0")
		}
	}
	return r.cli.get("/api/logs?" + q.Encode())
}

func (r *mcpRuntime) stats(args map[string]any) (any, error) {
	hours := intFrom(args["hours"], 24, 1, 720)
	return r.cli.get("/api/metrics/summary?hours=" + itoa(hours))
}

func (r *mcpRuntime) issuePasswordReset(args map[string]any) (any, error) {
	username := strings.TrimSpace(fmt.Sprint(args["username"]))
	if username == "" || username == "<nil>" {
		return nil, errors.New("username is required")
	}
	var out map[string]any
	if err := r.cli.post("/api/password/reset", map[string]any{"username": username}, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// --------------------------------------------------------------------------
// HTTP client

// mcpClient talks to the running echo server using the operator's credential.
type mcpClient struct {
	base  string
	token string // JWT (Bearer)
	key   string // X-API-Key
	h2    bool
	admin bool
	http  *http.Client
}

func newMCPClient() *mcpClient {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("ECHO_SERVER_URL")), "/")
	if base == "" {
		// Default to HTTPS: the TLS fingerprint and the UA-spoof verdict only
		// exist on a TLS connection, and an agent asking "do I look like Chrome"
		// cannot be answered over plain HTTP. The probe below falls back to the
		// plain port only when the TLS listener is unreachable.
		base = "https://127.0.0.1:" + defaultHTTPSPort
		if !probeReachable(base) {
			base = "http://127.0.0.1:" + defaultHTTPPort
		}
	}
	c := &mcpClient{base: base, key: strings.TrimSpace(os.Getenv("ECHO_SERVER_API_KEY"))}
	if c.key == "" {
		c.token = strings.TrimSpace(os.Getenv("ECHO_SERVER_TOKEN"))
	}
	// Self-signed cert is the norm for this server; directories opt in.
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	c.http = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	// Probe the credential's scope once: an admin key is visible to
	// /api/system/environment, a viewer key is not.
	if c.key != "" || c.token != "" {
		var ignored map[string]any
		c.admin = c.doMust(c.newRequestMust("/api/system/environment"), &ignored) == nil
	}
	return c
}

func (c *mcpClient) isAdmin() bool { return c.admin }

// probeReachable reports whether a listener answers /health.
func probeReachable(base string) bool {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	cl := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	resp, err := cl.Get(base + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (c *mcpClient) newRequest(path string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	if c.key != "" {
		req.Header.Set("X-API-Key", c.key)
	} else if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("User-Agent", "echo-server-mcp/"+mcpServerVersion)
	return req, nil
}

func (c *mcpClient) newRequestMust(path string) *http.Request {
	r, _ := c.newRequest(path)
	return r
}

func (c *mcpClient) do(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the echo server at %s: %w (set ECHO_SERVER_URL)", c.base, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			msg += " (check ECHO_SERVER_API_KEY / ECHO_SERVER_TOKEN, and that the key's scope allows this)"
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("response is not JSON: %w", err)
		}
	}
	return nil
}

func (c *mcpClient) doMust(req *http.Request, out any) error {
	if req == nil {
		return errors.New("bad request")
	}
	return c.do(req, out)
}

func (c *mcpClient) get(path string) (any, error) {
	req, err := c.newRequest(path)
	if err != nil {
		return nil, err
	}
	var out any
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mcpClient) getRaw(path string) ([]byte, error) {
	req, err := c.newRequest(path)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the echo server at %s: %w", c.base, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (c *mcpClient) post(path string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.key != "" {
		req.Header.Set("X-API-Key", c.key)
	} else if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("User-Agent", "echo-server-mcp/"+mcpServerVersion)
	return c.do(req, out)
}

// --------------------------------------------------------------------------
// Schema helpers

func objSchema(props map[string]any, required []string) map[string]any {
	s := map[string]any{"type": "object"}
	if props == nil {
		props = map[string]any{}
	}
	s["properties"] = props
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func strSchema(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func boolSchema(desc string) map[string]any {
	return map[string]any{"type": "boolean", "description": desc}
}

func numSchema(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func strListSchema(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

// toStringList accepts either a list of strings or a single comma/space
// separated string, because agents produce both shapes.
func toStringList(v any) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			add(fmt.Sprint(e))
		}
	case []string:
		for _, e := range t {
			add(e)
		}
	case string:
		for _, p := range strings.FieldsFunc(t, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\n' || r == ';'
		}) {
			add(p)
		}
	}
	return out
}

// intFrom reads a JSON number or string with bounds.
func intFrom(v any, def, lo, hi int) int {
	n := def
	switch t := v.(type) {
	case float64:
		n = int(t)
	case int:
		n = t
	case string:
		var parsed int
		fmt.Sscan(t, &parsed)
		n = parsed
	}
	if n < lo {
		n = lo
	}
	if n > hi {
		n = hi
	}
	return n
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// sortedKeys is a small helper used by diagnostics/tests.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
