---
name: echo-server
description: Use a self-hosted echo-server deployment to check an egress IP, identify the calling client from its TLS/HTTP2 fingerprint, look up IP geolocation/ASN, audit query traffic, and manage password resets. Trigger when the user asks "what is my IP", "does my proxy look like Chrome", "is this a datacenter IP", "who is hitting our endpoint", or wants to install/verify an echo-server instance.
---

# Echo Server

A self-hosted HTTP echo service that reports what it can see about the caller: the raw request,
the full TLS ClientHello (JA3/JA4), the HTTP/2 fingerprint, the client identity (including UA-spoof
detection), and the caller's IP with ASN/geolocation/connection type.

There are two ways to use it, and you should pick based on what the user is doing.

## 1. MCP tools (preferred when the server is already deployed)

If the deployment is reachable, use the MCP server instead of raw HTTP: it gives typed tools and
handles auth for you.

Register it (Claude Code):

```bash
claude mcp add echo-server \
  --env ECHO_SERVER_URL=http://127.0.0.1:23231 \
  --env ECHO_SERVER_API_KEY=esk_... \
  -- /path/to/echo-server mcp
```

Tools it exposes:

| Tool | Use it for |
|---|---|
| `echo_server_health` | Confirm the deployment is up before anything else |
| `echo_server_my_ip` | The egress IP this agent appears as (proxy/exit-node check) |
| `echo_server_self_fingerprint` | "Do I look like curl or Chrome?" — client name/family, JA3/JA4, h2 fingerprint, spoofed flag. Pass `user_agent` to test a forged UA |
| `echo_server_lookup_ip` | Country/region/city/coords/ASN/connection type for up to 100 IPs (`nocache: true` forces a fresh lookup) |
| `echo_server_search_ja4` | Look up a JA4 fingerprint or search by client name (`cobalt`, `chrome`, `curl`) |
| `echo_server_query_log` | Recent traffic; filter by `client`, `family`, `spoofed`, `type`, `country`, `ip` |
| `echo_server_stats` | Totals, top clients/families/countries, spoofed and unidentified counts |
| `echo_server_providers` | Which geo provider is degrading (calls/success/latency) |
| `echo_server_issue_password_reset` | Admin only: one-time reset token for a locked-out account |

Credentials: `ECHO_SERVER_API_KEY` (create one in 安全与防护, scope `admin` if you need the reset
tool) or `ECHO_SERVER_TOKEN` (an admin JWT). Without a credential, read-only tools still work only
if the server does not require auth; the reset tool always refuses, with a readable message.

## 2. Direct HTTP (when no MCP client is configured)

The plain endpoints are stable and need no protocol wrapper:

```bash
# egress IP, cheapest possible path (no TLS parsing, no log write)
curl -s http://HOST:23231/ip                  # {"ip":"203.0.113.42"}
curl -s 'http://HOST:23231/ip?format=text'    # 203.0.113.42

# full fingerprint of the caller
curl -sk 'https://HOST:23232/echo?fields=client,ja4,tls,http2,ip'
# -> client.name, client.family, client.spoofed, ja4, tls.ja3_hash, http2.raw, ip.country

# look up any address (needs a login/API key)
curl -sk -H "X-API-Key: $KEY" 'https://HOST:23232/api/ip/lookup?ip=8.8.8.8'

# traffic history
curl -sk -H "X-API-Key: $KEY" 'https://HOST:23232/api/logs?client=curl&limit=20'
```

Ports default to **23231 (plain HTTP / console)** and **23232 (HTTPS / TLS fingerprints)**;
`PORT` and `HTTP_PORT` override them.

## Installing an instance

```bash
# full product
curl -fsSL https://github.com/crawler-requests/echo-server/releases/latest/download/checksums.txt
# ...download the archive for this OS/arch, verify, extract, then:
ECHO_SERVER_ADMIN_USERNAME=admin ECHO_SERVER_ADMIN_PASSWORD='<strong>' ./echo-server

# lite build for a proxy pool: no database, /ip + /echo only
ECHO_SERVER_LITE=1 ./echo-server-lite
```

Verify with `curl -s http://127.0.0.1:23231/health` (`{"status":"ok"}`), then load
`http://127.0.0.1:23231/ui/` for the console.

## Interpreting results

- **`client.spoofed: true`** — the TLS fingerprint and the User-Agent disagree. Trust the TLS side
  (a real Chrome cannot produce curl's JA4), so the UA is forged.
- **`ip.connection_type`** — `datacenter` (hosting/cloud), `residential_proxy` (proxy/VPN/Tor exit),
  `unknown` (could not confirm; **not** evidence of a residential user).
- **`http2.raw`** — `SETTINGS|PRIORITY|PSEUDO_HEADERS`; two clients with identical JA3 still differ
  here. TLS impersonation tools often miss this layer.
- **`ip.anycast: true`** — the city/coordinates are meaningless; only country and ASN are usable.
- **Accuracy** — country is reliable (~97%); city is a hint, not evidence. Do not make security
  decisions on city alone.

## Common tasks

**"Is my proxy really looking like Chrome?"** → `echo_server_self_fingerprint`, compare `client.name`
and `client.family` with the UA you sent; expect `spoofed: false` for a faithful impersonation.

**"Where does this IP come from and is it a datacenter?"** → `echo_server_lookup_ip` with the IP; read
`country`, `asn`, `org`, `connection_type`.

**"Who has been hitting our endpoint?"** → `echo_server_query_log` with `family=malware` or
`spoofed=true` to surface the interesting traffic, then `echo_server_stats` for the shape of it.

**"A user is locked out."** → `echo_server_issue_password_reset` (admin credential). The returned
token is single-use and expires in 30 minutes; the user redeems it at `/ui/` under 忘记密码？.
If nobody can log in at all, fall back to the offline path:
`./echo-server -reset-password -user <name>`.
