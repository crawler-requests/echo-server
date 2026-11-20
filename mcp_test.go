package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The MCP session must answer the handshake the way clients expect: initialize
// advertises tools, and notifications get no reply (a reply to a notification
// breaks strict clients).
func TestMCP_InitializeAndToolCatalogue(t *testing.T) {
	r := &mcpRuntime{cli: &mcpClient{}, logf: func(string, ...any) {}}

	resp := r.handle(mcpRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "initialize"})
	if resp == nil || resp.Error != nil {
		t.Fatalf("initialize failed: %+v", resp)
	}
	body, _ := json.Marshal(resp.Result)
	var init struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      map[string]any `json:"serverInfo"`
	}
	_ = json.Unmarshal(body, &init)
	if init.ServerInfo["name"] != "echo-server" {
		t.Errorf("serverInfo.name = %v", init.ServerInfo["name"])
	}
	if _, ok := init.Capabilities["tools"]; !ok {
		t.Error("initialize must advertise the tools capability")
	}

	if r.handle(mcpRequest{Method: "notifications/initialized"}) != nil {
		t.Error("a notification must not produce a response")
	}

	resp = r.handle(mcpRequest{JSONRPC: "2.0", ID: json.RawMessage(`2`), Method: "tools/list"})
	body, _ = json.Marshal(resp.Result)
	var list struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"echo_server_health": false, "echo_server_my_ip": false,
		"echo_server_self_fingerprint": false, "echo_server_lookup_ip": false,
		"echo_server_search_ja4": false, "echo_server_query_log": false,
		"echo_server_stats": false, "echo_server_providers": false,
		"echo_server_issue_password_reset": false, // admin gate, checked below
	}
	for _, tool := range list.Tools {
		if _, ok := want[tool.Name]; !ok {
			t.Errorf("unexpected tool %q", tool.Name)
			continue
		}
		want[tool.Name] = true
		if tool.Description == "" {
			t.Errorf("%s has no description (agents rely on it)", tool.Name)
		}
		if tool.InputSchema == nil || tool.InputSchema["type"] != "object" {
			t.Errorf("%s schema = %v", tool.Name, tool.InputSchema)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("tool %q missing from tools/list", name)
		}
	}
}

// An admin-only tool must refuse a viewer/absent credential with a message the
// agent can read, not a protocol-level error it would crash on.
func TestMCP_AdminToolRefusesWithoutAdminCredential(t *testing.T) {
	r := &mcpRuntime{cli: &mcpClient{admin: false}, logf: func(string, ...any) {}}
	resp := r.handle(mcpRequest{
		JSONRPC: "2.0", ID: json.RawMessage(`5`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"echo_server_issue_password_reset","arguments":{"username":"root"}}`),
	})
	if resp == nil || resp.Error != nil {
		t.Fatalf("admin gate must be an in-band tool error, got %+v", resp)
	}
	body, _ := json.Marshal(resp.Result)
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatalf("result = %s", body)
	}
	if !res.IsError {
		t.Fatalf("admin gate must set isError; got %s", body)
	}
	if len(res.Content) == 0 || !strings.Contains(res.Content[0].Text, "admin-scoped credential") {
		t.Fatalf("refusal message = %s", body)
	}
}

func TestMCP_UnknownToolAndMethod(t *testing.T) {
	r := &mcpRuntime{cli: &mcpClient{}, logf: func(string, ...any) {}}

	resp := r.handle(mcpRequest{JSONRPC: "2.0", ID: json.RawMessage(`6`), Method: "tools/call",
		Params: json.RawMessage(`{"name":"nope","arguments":{}}`)})
	if resp.Error == nil || resp.Error.Code != -32602 {
		t.Fatalf("unknown tool error = %+v", resp.Error)
	}

	resp = r.handle(mcpRequest{JSONRPC: "2.0", ID: json.RawMessage(`7`), Method: "no/such"})
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("unknown method error = %+v", resp.Error)
	}
}

// toStringList accepts the shapes agents actually emit.
func TestMCP_ToStringList(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{[]any{"8.8.8.8", "1.1.1.1"}, "8.8.8.8,1.1.1.1"},
		{"8.8.8.8, 1.1.1.1", "8.8.8.8,1.1.1.1"},
		{"8.8.8.8\n1.1.1.1", "8.8.8.8,1.1.1.1"},
		{[]any{"8.8.8.8", "8.8.8.8"}, "8.8.8.8"},
	}
	for _, c := range cases {
		if got := strings.Join(toStringList(c.in), ","); got != c.want {
			t.Errorf("toStringList(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMCP_IntFrom(t *testing.T) {
	cases := []struct {
		in                any
		def, lo, hi, want int
	}{
		{float64(50), 20, 1, 200, 50},
		{"300", 20, 1, 200, 200}, // clamped
		{0, 20, 1, 200, 1},       // clamped up
		{nil, 20, 1, 200, 20},    // default
	}
	for _, c := range cases {
		if got := intFrom(c.in, c.def, c.lo, c.hi); got != c.want {
			t.Errorf("intFrom(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}
