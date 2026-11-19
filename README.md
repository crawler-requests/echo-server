# echo-server

**English** | [简体中文](README.zh-CN.md)

[![CI](https://github.com/crawler-requests/echo-server/actions/workflows/ci.yml/badge.svg)](https://github.com/crawler-requests/echo-server/actions/workflows/ci.yml)
[![Release](https://github.com/crawler-requests/echo-server/actions/workflows/release.yml/badge.svg)](https://github.com/crawler-requests/echo-server/actions/workflows/release.yml)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

HTTPS echo service for crawler debugging: echoes request headers/body, the **complete TLS ClientHello** (raw bytes, SNI, ALPN, cipher suites, extensions, JA3 **and JA4 / JA4_r / JA4_o**), the **HTTP/2 fingerprint** (SETTINGS order, PRIORITY frames, pseudo-header order — the layer that survives TLS impersonation), **identifies the calling client** (curl / python-requests / Node / Java / Go / OpenSSL / Chrome / … plus UA-spoof detection), and the client's public IP with **ASN + city-level geolocation** (country/region/city/postal/latitude/longitude) plus a **connection type** (`datacenter` / `residential_proxy` / `unknown`).

ClientHello capture is per-connection and **fragmentation-safe**: bytes are accumulated across TCP reads and handshake records until the whole hello is available, so it also works for large post-quantum hellos (~1.5 KB) and clients whose hello arrives in many small segments.

Single Go binary; embeds a React + Ant Design admin console at `/ui/`; SQLite-backed config, query history,
user accounts (`admin` / `viewer`, PBKDF2-SHA256 passwords, JWT sessions), named API keys, audit trail,
notifications, webhooks, saved log views, Prometheus metrics and an OpenAPI document.

**Lite build**: the same binary started with `ECHO_SERVER_LITE=1` runs with no database at all and serves
only `/ip` (your egress IP) and `/echo`. Measured **100,000 concurrent connections** with zero failures and
230k+ rps on a 32-core box. See [Lite build & concurrency](#lite-build--concurrency).

---

## Copy-paste prompts for AI agents

These are runnable prompts. Give one to **Claude Code**, **Codex**, Cursor, or any agent with shell access
and it will install, start, verify and (optionally) deploy this service end to end. Each prompt defines
**acceptance tests** so the agent knows when it is done instead of guessing.

### 1. Deploy the full product and verify it (Claude Code / Codex / any shell agent)

```text
Set up the echo-server service on this machine and verify it end to end.

Steps:
1. Fetch the latest release for this OS/arch from
   https://github.com/crawler-requests/echo-server/releases/latest
   (artifact pattern: echo-server_<version>_<os>_<arch>.tar.gz; .zip on Windows).
   Verify it against checksums.txt, then extract.
2. Start it:  ECHO_SERVER_DB=./echo.db ECHO_SERVER_ADMIN_USERNAME=admin \
              ECHO_SERVER_ADMIN_PASSWORD='<healthy-random-password>' \
              PORT=8443 HTTP_PORT=8080 ./echo-server
   Run it under nohup/systemd and confirm the process stays up for 10 seconds.
3. Acceptance tests — all must pass before you report success:
   - curl -sf http://127.0.0.1:8080/health            -> {"status":"ok"}
   - curl -sf http://127.0.0.1:8080/ip                -> JSON containing "ip"
   - curl -sf http://127.0.0.1:8080/ip?format=text    -> a bare IP address
   - curl -sf -k https://127.0.0.1:8443/echo | head   -> JSON with "headers" and "client_hello"
   - curl -sf -k -H 'User-Agent: curl/8.5.0' https://127.0.0.1:8443/echo?fields=client
                                                      -> "client.name" == "curl" (or curl-like)
   - curl -sf http://127.0.0.1:8080/ui/ | grep 'id="root"'   -> the console page loads
   - POST /api/login with the admin credentials returns a JWT.
4. Print the console URL (http://<lan-ip>:8080/ui/) and the admin username.
Report: what you ran, every test output, and the URL. If any check fails, fix it before reporting.
```

### 2. Deploy the lite build for a proxy/egress pool (no database)

```text
Deploy the echo-server LITE build, which is a stateless "what is my egress IP" endpoint.

Steps:
1. Download the lite release: tag prefix `lite-`, artifact
   echo-server-lite_<version>_<os>_<arch>.tar.gz, verify checksums, extract.
2. Start with no database at all:
     ECHO_SERVER_LITE=1 PORT=8443 HTTP_PORT=8080 ./echo-server-lite
3. Acceptance tests — all must pass:
   - curl -sf http://127.0.0.1:8080/ip                -> JSON containing "ip"
   - curl -sf http://127.0.0.1:8080/ip?format=text    -> a bare IP
   - curl -sf http://127.0.0.1:8080/echo?fields=ip.ip -> JSON with ip
   - curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ui/      -> 404
   - curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/config -> 404
   - No *.db / *.db-wal file appears in the working directory.
   - 1000 sequential requests all return 200 (loop with curl -sf).
4. Raise file-descriptor limits (ulimit -n 1048576) and note it in the report —
   it is what lets this binary hold ~100k connections.
Report the URL, the fetched IP via /ip, and confirm the no-database property.
```

### 2b. Prove the 100k-concurrency claim on this machine

This is an optional verification prompt: it runs the repo's own load generator (`tools/loadtest`) instead
of trusting the README table.

```text
Verify that the echo-server lite build really holds 100,000 concurrent connections on this machine.

1. Start it:  ECHO_SERVER_LITE=1 PORT=8443 HTTP_PORT=8080 ./echo-server &
   (or `go run .` from a checkout).
2. Apply the kernel limits the test needs:
     sudo sysctl -w net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535
     sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
     ulimit -n 1048576
3. Spread client source ports across several loopback addresses (a single source IP only has ~64k
   outgoing ports, which is a CLIENT limit):
     for ip in 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5; do sudo ip addr add $ip/8 dev lo; done
4. Hold connections:
     go run ./tools/loadtest -mode hold -c 100000 -addr 127.0.0.1:8080 \
       -la 127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5 -d 20s
   Acceptance: dialed==100000, failed==0. While it runs, read the server's RSS (ps -o rss).
   Expect roughly 7-8 KB per connection.
5. Drive requests over the same 100k connections:
     go run ./tools/loadtest -mode drive -c 100000 -path /ip -addr 127.0.0.1:8080 \
       -la 127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5 -d 12s
   Acceptance: dialed==100000, failed==0, errs==0, and rps > 100000.
6. Clean up: remove the extra loopback addresses (`sudo ip addr del ...`) and stop the server.
Report: dialed/failed/requests/rps from both runs, the measured RSS, and the core count of this machine.
If failures are non-zero, report the client-side error first — it is almost always source-port
exhaustion or a low ulimit, not the server.
```

### 3. Run the test suite / contribute a change

```text
Work on the echo-server repository (Go + React, single binary).

1. Install Go 1.26+ and Node 22.
2. make build        # builds frontend/dist then embeds it via //go:embed
3. Run the acceptance gate and fix anything that fails:
     gofmt -l .            (must print nothing)
     go vet ./...
     go test ./... -race -count=1
4. Make your change, re-run the full gate, and add a test that fails without the change.
5. Verify the running binary, not just the unit tests:
     PORT=18443 HTTP_PORT=18080 ./echo-server &
     curl -sf http://127.0.0.1:18080/ip
     curl -sf -k https://127.0.0.1:18443/echo?fields=ja4,tls,client
Report: the diff summary, the gate output, and the manual curl output.
```

### 4. Audit what this service can tell you about a client

```text
Start the echo-server and probe it from several clients to see the fingerprint surface.

1. Build and run: make build && PORT=8443 HTTP_PORT=8080 ./echo-server &
2. For each of these clients, capture the response from /echo?fields=client,ja4,tls,http2,ip and
   summarise name, family, JA4, HTTP/2 fingerprint and detected UA spoofing:
     curl, wget, python -c 'import requests; requests.get(...)', node, go net/http,
     a browser curl with a forged Chrome User-Agent.
3. Confirm: the forged Chrome UA from curl is flagged "spoofed": true, and the Go client's
   absent http2 fingerprint is distinguishable from curl's.
4. Report a table: client -> detected name/family -> JA4 -> h2 fingerprint -> spoofed.
```

## Run

```bash
make build                       # builds frontend/dist, then embeds it into ./echo-server
PORT=8443 ./echo-server          # HTTPS (TLS fingerprints) + plain HTTP console on :8080
```

`make build` runs `npm ci && npm run build` in `frontend/` first and then `go build`. The console is
embedded with `//go:embed frontend/dist`, so `./echo-server` is the **only file you deploy** — no static
directory, no Node runtime, no reverse proxy required. Building the frontend by hand? Run
`cd frontend && npm ci && npm run build` before `go build`, otherwise the binary embeds a stale UI.

The admin console is served over **plain HTTP on port 8080** by default, so opening
`http://HOST:8080/ui/` needs no self-signed-certificate exception. The HTTPS listener on `PORT` (default
8443) serves the same UI/APIs **and** captures the TLS ClientHello/JA3/JA4 that plain HTTP cannot provide.
Set `HTTP_PORT=8080` to move the plain listener, or `HTTP_PORT=0` to disable it and stay HTTPS-only.

### Run with Docker

```bash
docker build -t echo-server .
docker run -d --name echo-server \
  -p 8080:8080 -p 8443:8443 \
  -v echo-data:/data \
  -e ECHO_SERVER_ADMIN_USERNAME=admin \
  -e ECHO_SERVER_ADMIN_PASSWORD='change-me-please' \
  echo-server
```

The image is a small Alpine runtime with the same self-contained binary (CA roots and tzdata
included); the SQLite database lives on the `/data` volume. Omit the `ECHO_SERVER_ADMIN_*`
variables to use the first-run setup wizard at `/ui/` instead.

## Lite build & concurrency

`ECHO_SERVER_LITE=1` starts the binary in lite mode: **no SQLite, no users, no datasets, no admin API, no
query log**. It serves `/ip`, `/echo`, `/health` and `/metrics`; everything else answers 404. This is the
build to point a proxy pool, a crawler fleet or an egress checker at.

| Mode | Concurrency | Throughput | Failures | Server CPU |
|---|---|---|---|---|
| lite `/ip` | 1,000 | 217k rps | 0 | ~2 cores |
| lite `/ip` | 10,000 | 298k rps | 0 | ~2 cores |
| lite `/ip` | 50,000 | 221k rps | 0 | ~2 cores |
| lite `/ip` | **100,000** | **230k–256k rps** | **0** | **~2 cores** |

100k *concurrent* connections (held open) used **713 MB RSS** (~7.1 KB per connection) and zero failed
connections; driving requests over those 100k connections gave **231k rps with zero errors**. The load
generator needed 13+ cores for the same test, so these numbers are client-bound, not server-bound.

### Reproduce it

The generator is in the repo (`tools/loadtest`), so the numbers above are verifiable rather than
asserted:

```bash
# kernel limits (server and client side)
sudo sysctl -w net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"   # client side only
ulimit -n 1048576

# 1) start the lite server
ECHO_SERVER_LITE=1 PORT=8443 HTTP_PORT=8080 ./echo-server &

# 2) hold 100k connections open (memory per connection)
go run ./tools/loadtest -mode hold -c 100000 -addr 127.0.0.1:8080 \
  -la 127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5 -d 20s

# 3) drive requests over 100k connections (throughput)
go run ./tools/loadtest -mode drive -c 100000 -path /ip -addr 127.0.0.1:8080 \
  -la 127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5 -d 12s
```

A single host's own source ports cap it at ~64k *outgoing* connections per source IP; that is why the
client is spread across five loopback addresses (`-la`). Serving 100k **inbound** connections needs only
the server-side limits above — a real fleet of clients reaches it with a single source IP each.

## Fast path: `/ip`

If all you need is *the caller's egress IP*, do not pay for the full echo machinery (ClientHello
parsing, JA3/JA4/JA4H/h2 fingerprints, client identification, geolocation, query-log write). `GET /ip`
answers exactly that and nothing else:

```bash
curl -k https://HOST:8443/ip                   # {"ip":"203.0.113.42"}
curl -k https://HOST:8443/ip?format=text       # 203.0.113.42
curl -k http://HOST:8080/ip                    # plain HTTP listener, no TLS at all
```

It honours `X-Forwarded-For` / `X-Real-IP` / `CF-Connecting-IP` the same way `/echo` does, returns
`Cache-Control: no-store`, and is counted in `/metrics` as `echo_ip_only_requests_total`. It deliberately
writes no query-log row, so a proxy-pool health check does not drown the console history.

Measured on a 32-core machine (loopback, plain HTTP, `ab -k` and a Go load generator):

| Endpoint | Concurrency | Throughput | p50 | p99 |
|---|---|---|---|---|
| `/ip` | 1,000 | **127k rps** | 0.8 ms | 38 ms |
| `/ip` | 5,000 | 102k rps | 44 ms | 182 ms |
| `/echo` (full body) | 1,000 | 53k rps (plain) / 29k (TLS) | 5.8 / 4.6 ms | 145 / 515 ms |

At 2,000 concurrent connections the server used ~2.5 cores while the load generator needed 13, so the
figures above are limited by the client, not the server. Real remote clients add network RTT and TLS
handshake cost to these numbers; keep-alive (as every pooled crawler uses) is what the table reflects.

## Echo endpoint — request controls

All knobs are optional. Resolution order: **query param > header > admin default**.

| Control | Query | Header | Values |
|---|---|---|---|
| Format | `format` | `X-Echo-Format` | `json` (default) / `text` |
| Fields | `fields` | `X-Echo-Fields` | comma-separated dot paths |

```bash
# everything (default)
curl -k https://HOST:8443/echo

# only what you need, as text — smallest response
curl -k -H 'X-Forwarded-For: 8.8.8.8' \
  'https://HOST:8443/echo?format=text&fields=ip.country,ip.city,ip.latitude,ip.longitude,ip.connection_type'
# ip.city=San Jose
# ip.connection_type=datacenter
# ip.country=United States
# ip.latitude=37.3393939
# ip.longitude=-121.8949553

# same fields as JSON
curl -k 'https://HOST:8443/echo?format=json&fields=client_hello.sni,client_hello.ja3_hash,ip.asn,ip.org'

# just the client verdict (who is calling, and whether its UA is honest)
curl -k 'https://HOST:8443/echo?fields=client.name,client.family,client.spoofed,client.confidence'
# {"client":{"confidence":0.88,"family":"cli","name":"curl","spoofed":true}}
```

## Response shape (abridged)

```jsonc
{
  "timestamp": "...", "method": "GET", "scheme": "https", "host": "...", "remote_addr": "...",
  "path": "/echo", "http_version": "HTTP/1.1",
  "headers": { "...": ["..."] }, "body": "", "body_length": 0,
  "client_hello": {
    "raw_base64": "...", "raw_hex": "...", "raw_record_base64": "...",
    "length": 512, "record_length": 517, "record_count": 1, "record_version": 771,
    "version": 771, "cipher_suites": [4866, 4867, 4865], "extensions": [11, 10, 16, 43, 13, 51],
    "sni": "example.com", "alpn": ["h2", "http/1.1"],
    "supported_versions": [772, 771], "signature_algorithms": [1027, 1283], "supported_groups": [29, 23],
    "key_share_groups": [29], "has_grease": false,
    "ja3": "771,4866-...", "ja3_hash": "...",
    "ja4": "t13d3112h2_e8f1e7e78f70_b26ce05bbdd6", "ja4_r": "t13d...", "ja4_o": "t13d..."
  },
  "client": {
    "name": "curl", "family": "cli", "version": "8.5.0", "confidence": 0.95,
    "signal": "ja4_measured+user_agent", "source": "user_agent",
    "matches": ["JA4 exact match: t13i3111h2_…", "User-Agent: curl/8.5.0", "TLS family and User-Agent agree"],
    "header_set_hash": "a1b2c3d4e5f6"
  },
  "ja4h": "ge11nn020000_e5a56608905c_000000000000_000000000000",
  "tls": {
    "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "server_name": "example.com", "alpn": "h2",
    "ja3_string": "...", "ja3_hash": "...", "ja4": "...", "ja4_r": "...", "ja4_o": "..."
  },
  "ip": {
    "ip": "8.8.8.8", "asn": "AS15169", "org": "Google LLC", "isp": "Google LLC",
    "country": "United States", "country_code": "US", "region": "California", "city": "San Jose",
    "postal": "95025", "timezone": "America/Los_Angeles", "utc_offset": "-08:00", "continent": "North America",
    "latitude": 37.3393939, "longitude": -121.8949553,
    "connection_type": "datacenter", "geo_source": "ipwhois"
  }
}
```

`connection_type` = `datacenter` (hosting/cloud CIDR table + org-name heuristic, or ipinfo `hosting`),
`residential_proxy` (published residential-proxy exits, or ipinfo `proxy`/`vpn`/`tor`), else `unknown`.

## Client identification

`client` answers *what is calling me?* by combining the TLS fingerprint (hard to forge) with the User-Agent:

- **JA4 fingerprint providers** — an embeddable/pluggable database of real-world JA4 fingerprints maps the
  ClientHello to the clients that actually send it. Like every data set in the server, it is assembled from
  priority-ordered providers (see [Data-source engine](#data-source-engine-providers)), with the embedded
  fused library always as the final fallback.

  The embedded library is itself a fusion: the JA4DB crowd snapshot (what User-Agents really accompany each
  fingerprint) **plus** FoxIO's curated mapping (application names that no submission database carries —
  Cobalt Strike, Sliver, Qakbot, IcedID, Lumma, Pikabot, Darkgate, ngrok, SoftEther). Curated malware matches
  report `family: "malware"`, tunnel/VPN tools `family: "tunnel"`, and every match carries the OS/library
  context its submissions recorded (`client.os`, `client.library`, `client.fused`).

  Lookup walks providers from highest priority to lowest, exact JA4 first, then JA4 prefix (head + cipher hash,
  which browsers keep across releases). The first provider that knows the fingerprint wins, so a private or
  cloud-synced library overrides the snapshot for the fingerprints it covers; everything else still resolves
  through the snapshot. A custom provider's verdict is reported as `source: "ja4db:<provider>"`.

- **TLS table** — exact JA4, then exact JA3 hash, then family heuristics, from fingerprints measured against this
  server: curl, wget (GnuTLS), python-requests, Node.js, Java 21, OpenSSL, Go net/http, Chromium.
- **User-Agent** — curl / wget / python-requests / aiohttp / httpx / node-fetch / okhttp / Postman / Java /
  Go-http-client / Chrome / Edge / Opera / Firefox / Safari / HeadlessChrome / Googlebot & friends, with version.
- **Header set** — `header_set_hash` plus a browser-like hint.

Two database tiers keep the snapshot useful as it ages: an **exact JA4** match, and a **JA4 prefix** match (the
head + cipher hash, which browsers keep stable across releases while their extension hash changes). A newer
Chrome build that is absent from the snapshot still falls back to the prefix tier and is named Chrome from 55k
observations. Because some fingerprints are genuinely shared (Go 1.24+ and Chrome both send the post-quantum
`X25519MLKEM768` key share, and JA4DB sees plenty of crawlers wearing a Chrome UA), the answer carries
`candidates` (each plausible client with its share of the observations), `db_observations`, and a note when the
top candidate disagrees with our own measurement — the server never pretends TLS alone settles a shared
fingerprint.

`family` is one of `browser | cli | library | runtime | tool | bot | http_client`. When the UA contradicts the
TLS handshake the request is flagged `spoofed: true`, the **TLS result is reported as the identity**, and the note
spells out both sides:

```bash
curl -k -A 'Mozilla/5.0 … Chrome/131.0.0.0 Safari/537.36' https://HOST:8443/echo?fields=client
# {"client":{"name":"curl","family":"cli","spoofed":true,"confidence":0.88,
#   "notes":["TLS fingerprint says curl (cli) but the User-Agent claims Chrome (browser) — the UA is very likely spoofed"]}}
```

### Data-source engine (providers)

Every data set the server consults is one *dataset*, assembled from priority-ordered *providers*. The same four
provider kinds work for all of them, and the compiled-in data is always the lowest-priority `builtin` fallback:

| kind | source | refresh |
|---|---|---|
| `embedded` | compiled into the binary (`builtin`, immutable) | never |
| `file` | a local file **or directory** (every decodable file inside is merged) | optional interval (mtime watch) + manual reload |
| `remote` | a URL (`http`/`https`, or any scheme registered with `datasets.RegisterScheme`) | optional interval + manual sync |
| `command` | stdout of a shell command — implement a data source in any language | optional interval + manual sync |

`refresh_min` on a `file` provider turns that provider into a watched file: the engine stats it (a directory: its newest non-hidden file) every interval and reloads atomically when the timestamp moves, so a mounted ConfigMap or a nightly export is picked up without a restart. An interval of `0` means manual only. Remote providers accept `headers` (e.g. `{"Authorization":"Bearer …"}`) for private clouds; secret values are masked (`***`) in every API response, and posting the mask back keeps the stored value.

The datasets shipped today:

| dataset | what it feeds |
|---|---|
| `ja4` | TLS fingerprint → client name (JSON contract or community `ja4_fingerprint.csv`) |
| `datacenter_cidr` | CIDR prefixes classified `datacenter` (union of all providers + embedded table) |
| `residential_proxy_cidr` | CIDR prefixes classified `residential_proxy` |
| `datacenter_orgs` | ASN/org-name keywords used as the hosting fallback heuristic |

Remote and command payloads are cached on disk (`~/.echo-server/datasets/<dataset>/<provider>.data`, override with
`ECHO_SERVER_DATASET_CACHE_DIR`), together with the last HTTP `ETag`, so a restart revalidates with
`If-None-Match` (a 304 keeps the cached copy) instead of re-downloading. A restart — or an unreachable cloud —
keeps the last good data in effect. A failed refresh reports an error in the provider status but never drops the
working value. Fetches and decodes run outside the manager lock: a slow cloud or a large library never blocks
status/API calls, and a result that arrives after the provider was reconfigured is discarded. Providers are persisted
in the SQLite config table under `dataset_providers:<name>` and can also be seeded at startup with the
`DATASET_PROVIDERS` environment variable (a JSON object keyed by dataset name). The admin UI's *数据源（Provider）*
card drives the same API: pick a dataset, add/edit/sync/delete its providers.

```bash
# list every dataset with its providers and live status (entries, observations, last sync, errors)
curl -k -H "Authorization: Bearer $JWT" https://HOST:8443/api/datasets
# …or just one dataset (returns the object, not an array)
curl -k -H "Authorization: Bearer $JWT" 'https://HOST:8443/api/datasets?dataset=ja4'

# add a local library or directory to the JA4 dataset (watch it for changes every 5 minutes)
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"my-fp","kind":"file","priority":10,"path":"/data/my-ja4db.json","refresh_min":5}' \
  'https://HOST:8443/api/datasets?dataset=ja4'

# pull a private cloud library every 30 minutes, authenticating with a header
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"cloud","kind":"remote","priority":20,"url":"https://cloud.example.com/ja4db.json",
       "headers":{"Authorization":"Bearer CLOUD_TOKEN"},"refresh_min":30}' \
  'https://HOST:8443/api/datasets?dataset=ja4'

# generate a datacenter CIDR table with any script (stdout is the data)
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"nightly","kind":"command","priority":10,"command":"/opt/gen-cidrs.sh","refresh_min":720}' \
  'https://HOST:8443/api/datasets?dataset=datacenter_cidr'

# force a sync now (all providers of a dataset, or ?provider=NAME — a file provider is re-read);
# DELETE removes a custom provider
curl -k -X POST -H "Authorization: Bearer $JWT" 'https://HOST:8443/api/datasets/sync?dataset=ja4&provider=my-fp'
curl -k -X DELETE -H "Authorization: Bearer $JWT" 'https://HOST:8443/api/datasets?dataset=ja4&provider=cloud'
```

The JA4 cloud contract is the same `{meta, ja4}` JSON that `tools/ja4dbgen` writes —
`{"ja4": {"<fingerprint>": {"n": observations, "uas": [[ua, count], …], "apps": …}}}`. The engine itself
(`datasets/`) is generic: an embedder adds a whole new data set with `datasets.New`, plugs a transport with
`datasets.RegisterScheme`, and the admin API/UI expose it automatically.

### IP-intelligence lookup chain (providers)

Geolocation, ASN and privacy answers come from a *lookup chain*: an ordered list of providers queried one IP at a
time. The chain is tried in priority order and the first provider that returns usable data wins; a provider that
is rate-limited, times out, errors or has no data is recorded and the next one is tried. Several cloud APIs can be
chained, so a free API can be the cheap default and a paid/token API the fallback (or the other way round).

| kind | source | answer |
|---|---|---|
| `builtin` | a driver compiled into the binary (`ipwhois`, `ipapi`, `ipinfo`) | normalized fields in Go |
| `http` | any HTTP API URL template with `{ip}` (escaped) or `{ip_raw}` | JSON, optionally mapped |
| `command` | stdout of `sh -c '<command>'` with `{ip}` substituted | JSON, optionally mapped |

A response already in the normalized shape (`country`, `country_code`, `region`, `city`, `postal`, `timezone`,
`utc_offset`, `latitude`, `longitude`, `continent`, `asn`, `asn_name`, `org`, `isp`, `is_proxy`, `is_vpn`,
`is_tor`, `is_hosting`, `anycast`) needs no mapping. Other APIs are described with `mapping` (Info field → dot path, array
indexes supported): `{"country":"data.location.country_name","latitude":"data.location.lat","asn":"data.asn"}`.
`headers` carry credentials; as with datasets they are masked (`***`) in every API response, and posting the mask
back keeps the stored secret. Per-provider statistics (calls, successes, failures, average latency, last error,
last success) are exposed through the API/UI, so a silently degrading upstream is easy to spot.

```bash
# list the chain: config (credentials masked), ordering and live stats
curl -k -H "Authorization: Bearer $JWT" https://HOST:8443/api/ipproviders

# append a paid cloud API; it is tried before the built-ins when its priority is higher
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"cloud","kind":"http","enabled":true,"priority":100,
       "url":"https://api.example.com/v1/ip/{ip}",
       "headers":{"Authorization":"Bearer CLOUD_TOKEN"},
       "mapping":{"country":"data.country","city":"data.city","asn":"data.asn",
                  "is_proxy":"data.privacy.proxy","is_hosting":"data.privacy.hosting"}}' \
  https://HOST:8443/api/ipproviders

# try a local script (any language) as another link in the chain
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"name":"local","kind":"command","enabled":true,"priority":-10,
       "command":"/opt/ipintel.sh {ip}","timeout_sec":3}' \
  https://HOST:8443/api/ipproviders

# query one IP through the chain without touching the result cache
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"ip":"8.8.8.8"}' https://HOST:8443/api/ipproviders/test

# remove a custom provider (built-ins can be disabled but not deleted)
curl -k -X DELETE -H "Authorization: Bearer $JWT" 'https://HOST:8443/api/ipproviders?name=cloud'
```

The chain is persisted in SQLite under `ip_lookup_providers` and can be seeded with the `IP_LOOKUP_PROVIDERS`
environment variable (a JSON array, applied after the persisted list). The legacy settings keep their meaning:
`enable_online_geo=false` disables the whole chain; `geo_provider=ipwhois|ipapi|ipinfo` runs only that built-in
(custom providers still take part); `geo_provider=auto`/unset runs everything, and a configured `ipinfo_token`
boosts the `ipinfo` built-in to the front of the chain. Built-ins ship enabled at priorities `ipwhois=20`,
`ipapi=10`, `ipinfo=5`. The admin UI's *IP 查询链路（Provider）* card drives the same API, including a per-IP
"test the chain" button.

### JA4H (HTTP-layer fingerprint)

`ja4h` is the HTTP companion to JA4 (FoxIO spec): method, HTTP version, cookie/referer presence, the header-name
set, Accept-Language, and cookie fields/values, hashed. It cannot be spoofed by changing the User-Agent alone and
separates clients that share one TLS stack at the HTTP layer. `show_ja4h` (admin toggle, default on) controls it.
One deviation from the reference is forced by Go's `http.Server`: header **names are sorted** before hashing (the
wire order is unrecoverable from `http.Header`, and `Host` lives in `r.Host`, not the header map); the cookie
field/value hashes match the reference byte-for-byte.

### HTTP/2 fingerprint

TLS impersonation tools (curl_cffi, uTLS) copy a browser's JA3/JA4 perfectly, which is why the HTTP/2 layer
is the next discriminator: browsers and HTTP libraries differ in the SETTINGS they send, whether they use
PRIORITY frames, and the order of the request pseudo-headers. The echo response carries an `http2` object
when the connection negotiated h2:

```json
{
  "http2": {
    "raw": "3:100,4:10485760,2:0|:method,:scheme,:authority,:path",
    "settings": "3:100,4:10485760,2:0",
    "pseudo_header_order": [":method", ":scheme", ":authority", ":path"],
    "stream_id": 1
  }
}
```

`raw` is the widely used Akamai-style fingerprint: `SETTINGS|PRIORITY|PSEUDO_HEADERS`. The server runs
`golang.org/x/net/http2` itself so SETTINGS and PRIORITY frames — which Go's `net/http` discards — can be
recorded off the raw connection; the request handling (mux, auth, middleware, echo) is unchanged.
HTTP/1.x connections carry no `http2` object. `enable_http2=false` pins the listener to HTTP/1.1 only;
it is read when the TLS config is built, so it takes effect after a restart.

Measured with real clients against one instance: curl sends
`3:100,4:10485760,2:0|:method,:scheme,:authority,:path`, while Go's `net/http` sends
`2:0,4:4194304,5:16384,6:10485760|:authority,:method,:path,:scheme` — different SETTINGS order **and** a
different pseudo-header order.

### Credential headers are masked by default

The echo endpoint is often reachable by anyone, and reflecting request headers verbatim makes every
request a credential leak in logs, screenshots and shared `curl` output. `redact_sensitive_headers`
(default **on**) replaces the value of `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`,
`X-Api-Key`, `X-Api-Token`, `X-Auth-Token` and `X-Csrf-Token` with `***` (`Bearer ***` keeps the scheme
so you can still tell Bearer from Basic). Turn it off in *回显设置* only when debugging token handling.

### Operations notes

- **Graceful shutdown**: `SIGINT`/`SIGTERM` stops accepting, drains in-flight requests for up to 15 s
  (they may be waiting on a geo lookup or a large upload), closes SQLite, then exits.
- **Echo body cap**: 8 MB by default even with `body_limit_kb=0`, because the handler reads the whole
  body into memory. Set `body_limit_kb` to a smaller value for a tighter cap.
- **Rate limiting and IP rules** charge both the claimed client address (`X-Forwarded-For`) and the TCP
  peer, so rotating a spoofed header cannot escape the per-minute budget or an allowlist.
- **Login / setup / register** are throttled per TCP peer (10 failures or 30 attempts per 15 minutes).
  This throttle is always on and independent of `rate_limit_per_min`.
- **SQLite indexes**: `query_log` is indexed on `ts`, `ip` and `(connection_type, country)`; `audit_log`
  on `ts`, `username` and `action`; plus `notifications(read, ts)`, `api_keys(key_hash)`,
  `webhooks(enabled)` and `saved_views(page)`. `TestQueryLogIndexesAreUsed` asserts the planner picks
  them for the console's filter shapes.

### Regenerating `data/ja4db.json` (multi-source fusion)

The built-in library is a **fusion of two sources**, because each covers what the other misses:

| Source | Contributes |
|---|---|
| JA4DB public-API snapshot (frozen 2026-05-15, mirrored by `github.com/Niicolaa/ja4db-export`) | 1,589 fingerprints, ~320k real submissions: which User-Agents actually accompany a fingerprint, with OS/library rows |
| FoxIO `ja4plus-mapping.csv` (`github.com/FoxIO-LLC/ja4`) | hand-curated application names — including malware C2s and tunnel tools no submission database carries: Cobalt Strike, Sliver, Qakbot, IcedID, Lumma, Pikabot, Darkgate, SoftEther, ngrok, Telegram |

Rebuild both sources at once:

```bash
go run ./tools/ja4dbgen                      # downloads both mirrors, writes data/ja4db.json
go run ./tools/ja4dbgen -ja4db X.csv -mapping Y.csv   # or use local copies
```

The generator pins the JA4DB snapshot to the last full export commit (`4e46ad5b4401`): the moving
`@main` ref now serves a truncated 596-fingerprint file, while that commit has the full 1,633. Curated
names are weighted against the fingerprint's submission volume so a hand-verified malware match is
visible without drowning real traffic. The output keeps the `{meta, ja4}` contract, so every custom
provider (file/remote/command) that speaks the same JSON layers on top unchanged.

The fusion shows up in the output: malware-only fingerprints (`t13d201100_…` → IcedID, 423 observations;
`t12d190800_…` → Cobalt Strike beacon; `t13i190800_…` → Sliver Agent) are named, their `family` is
`malware`, and every fingerprint carries the OS/library context its submissions recorded.

## ClientHello fingerprints

- **JA3** — `version,ciphers,extensions,curves,point_formats` in wire order with GREASE kept, hashed with **real MD5** (`ja3_hash`).
- **JA4** — per the FoxIO spec: `t` + TLS version (2 chars) + SNI flag (`d`/`i`) + 2-digit cipher count + 2-digit extension count + ALPN first/last char, then `_<12-hex of sorted non-GREASE ciphers>_<12-hex of sorted non-GREASE extensions minus SNI/ALPN + "_" + signature algorithms>`.
- **JA4_r / JA4_o** — the same layout with raw (unhashed) values: sorted (`_r`) and original wire order (`_o`).

## Admin UI & API

`/ui/` — React + Ant Design console backed by a SQLite user system. **A fresh installation has no accounts
and no default password.** Open `/ui/` and the setup wizard asks you to choose the first admin's username and
password; the account that it creates owns the installation. Complete this immediately after installing:
until an account exists, anyone who can reach the port can claim the first admin. For headless deployments,
set `ECHO_SERVER_ADMIN_USERNAME` (default `admin`) and `ECHO_SERVER_ADMIN_PASSWORD` before the first start instead.
Passwords are stored as salted PBKDF2-SHA256 (210k iterations). The JWT signing key comes from
`ECHO_SERVER_JWT_SECRET` or is generated once and persisted in SQLite, so sessions survive restarts.

Accounts have a role: `admin` manages users and configuration; `viewer` gets a read-only console (every mutating
request is rejected server-side, and the UI hides/disables the edit controls). A disabled or deleted user loses
access immediately (every request re-reads the account), and the last enabled admin cannot be deleted, disabled
or demoted. Admins control *允许访客自助注册* in the user-management card (off by default). While it is off, only
admins can create accounts; while it is on, the login page offers signup and every self-registered account is a
viewer.

The console is a single-page app with a grouped, collapsible sidebar and a `Ctrl/⌘+K` page palette. Each
section is its own route (`/ui/users`, `/ui/logs`, …), so links and refreshes work; the server falls back to
`index.html` for extension-less paths while missing assets still return 404.

| Page | Route | What it does |
|---|---|---|
| 概览 | `/ui/` | counters, 24h trend, latest notifications, quick actions, provider health |
| 回显设置 | `/ui/echo` | `show_*` toggles, response-field matrix, live JSON/text preview, per-request controls and presets |
| IP 定位查询 | `/ui/lookup` | query any IP by name (single/batch up to 100, `nocache`), map preview, connection/privacy tags, query-log history for that IP |
| IP 情报 | `/ui/ip` | online lookup switches, token, cache TTL, provider health table, chain test, field/privacy reference |
| 数据源 | `/ui/datasets` | cross-dataset stats, per-dataset providers (embedded/file/remote/command), sync, merge order, field reference |
| IP 查询链路 | `/ui/chain` | chain stats and order visualization, per-provider stats, per-IP test, normalization fields, config samples |
| JA4 指纹库 | `/ui/fingerprints` | cross-provider fingerprint search, candidate distribution, provider health |
| 监控分析 | `/ui/monitor` | 6h/24h/7d trends, top IPs/countries/methods, system resources, metrics links |
| 查询日志 | `/ui/logs` | server-side filters + quick presets, 24h trend and top IP/country, CSV/JSON export, saved views, detail drawer, request replay |
| 审计日志 | `/ui/audit` | stats, action/actor filters, action distribution and actor ranking, detail drawer, action dictionary, CSV export |
| 通知中心 | `/ui/notifications` | stats, level/keyword filters, source distribution, trigger rules, lifecycle table, unread badge, cleanup |
| 用户管理 (admin) | `/ui/users` | stats, search/role/status filters, accounts and roles, permission matrix, recent account activity, onboarding guide |
| 访问控制 | `/ui/access` | require-token switch, shared token with strength meter, endpoint auth matrix, code samples, security checks, recent events |
| 安全与防护 | `/ui/security` | overview score + checklist, named API keys, auth precedence, IP allow/deny rules, rate limit, body cap, CORS, maintenance mode, retention, backup, JWT rotation |
| 集成与 Webhook (admin) | `/ui/integrations` | webhook CRUD, event catalogue, delivery log, signature-verification samples, signed test delivery, backup/config downloads |
| 系统设置 | `/ui/system` | site name/description/timezone, runtime info, data exports, non-secret environment |
| API 文档 | `/ui/docs` | searchable endpoint catalogue, copyable curl, OpenAPI link |
| 工具箱 | `/ui/tools` | 4 grouped tabs: CIDR calculator, IPv4 base conversion, URL parser, special-range reference, Base64, URL codec, JSON formatter, timestamp, SHA/HMAC, token generator, JWT decode, UUID v4, password strength, curl builder, UA parser, HTTP status reference, regex tester |
| 我的账户 | `/ui/account` | profile, JWT claims and expiry countdown, password strength, personal audit trail, permission summary |

### Security controls (API keys, IP rules, maintenance)

Configuration keys added for the security page: `ip_allowlist` / `ip_denylist` (IP, CIDR, comma or newline
separated; deny wins, an empty allowlist means allow-all), `rate_limit_per_min` (charged against both the
claimed IP and the TCP peer, echo traffic only, `0` disables), `body_limit_kb` (echo request body cap; `0` keeps
the built-in 8 MB cap), `cors_origins`, `security_headers`,
`maintenance_mode` / `maintenance_message` (unauthenticated echo calls get `503`, the console/API stay usable),
`log_retention_days` (background purge every 6 hours) and the site keys `site_name` / `site_description` /
`timezone` / `locale` / `density`. IP rules, rate limiting and maintenance mode apply to echo traffic only, so the
console never locks the operator out. Login/setup/register carry a separate, always-on per-TCP-peer throttle.

Named API keys (`/api/apikeys`) are an alternative to the shared token: the plaintext `esk_…` secret is
returned **once** on creation, only its SHA-256 is stored, each key has a scope (`viewer`/`admin`) and an
optional expiry, and `last_used` is updated asynchronously. Send it as `X-API-Key`; a valid JWT always wins.
Keys can be disabled or deleted without touching accounts.

### Audit, notifications and webhooks

`/api/audit` records every mutating console action (account, config, security, system, API-key and webhook
changes) with actor, action, target, detail, IP and timestamp; it filters by action prefix and username and
exports CSV. `user.*`, `security.*`, `config.*` and `system.*` events also create in-app notifications
(`/api/notifications`) that drive the header badge. Webhooks (`/api/webhooks`) POST a JSON payload to any URL for
subscribed events, signed with `X-Echo-Signature: sha256=<hmac>` over the body using the per-webhook secret
(`X-Echo-Event` carries the event name); delivery is asynchronous with an 8s timeout, and failures raise a
warning notification. A test endpoint (`POST /api/webhooks/test`) sends a sample payload immediately.

### Observability, export, backup and replay

- `GET /metrics` — Prometheus text (queries total/today, users, uptime, goroutines, memory, DB size, enabled
  API keys/webhooks, unread notifications).
- `GET /api/metrics/summary?hours=N` — totals, unique IPs, hourly series (gap-filled), top IPs/countries/methods
  and connection types for the monitoring page and dashboard chart.
- `GET /api/openapi.json` — OpenAPI 3.0.3 (Bearer + API-key security schemes); `GET /api/endpoints` — the same
  catalogue in a compact form for the API-docs page.
- Exports: `/api/export/logs.csv|json`, `/api/export/users.csv|json`, `/api/export/config.json` (secrets
  excluded) and `/api/audit/export.csv`.
- `GET /api/system/backup` — consistent `VACUUM INTO` copy of the SQLite database, streamed as a download.
- `GET /api/system` — version, runtime, uptime, goroutines/GC, memory, DB path/size, ports, maintenance flag.
- `POST /api/system/purge-logs {days|all}` and `POST /api/system/rotate-jwt` (the latter refuses when the secret
  comes from `ECHO_SERVER_JWT_SECRET` and returns a fresh token).
- `POST /api/replay {method,path,headers,body}` — runs the real `echoHandler` in-process through `httptest`, so a
  logged request can be re-executed with different headers/body (e.g. to confirm a UA-spoof verdict) without
  leaving the console. Replays are not written to the query log.
- `GET /api/views` — saved log filter views (per page), shared across admins.

Configure which fields are exposed, default format, online IP-intel provider/cache/token, and the API token.
When *require API token* is on, echo requests need `X-API-Token: <token>` (or `?token=<token>`) or a valid JWT.
`GET /api/config` returns `api_token` only to admins; viewers see `***`.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/setup/status` | — | `{needs_setup,allow_registration,registration_open}` for the login/setup page |
| `POST /api/setup` | — (only while no accounts exist) | `{username,password}` → first account (always admin) + token |
| `POST /api/login` | — | `{username,password}` → `{token,user}` |
| `POST /api/register` | — (admin must enable registration) | `{username,password}` → viewer account + token; 403 when disabled |
| `GET /api/me` | JWT | current account and effective role |
| `POST /api/me/password` | JWT | `{old_password,new_password}` — rotate your own password |
| `GET/POST /api/users` | admin JWT | list accounts / create or update one (`{username,password?,role,disabled?}`) |
| `DELETE /api/users?username=` | admin JWT | remove an account (self-deletion and the last admin are rejected) |
| `GET/POST /api/config` | JWT (write: admin) | read/update config keys (including `allow_registration`) |
| `GET/POST/DELETE /api/datasets` | JWT / admin write | list every dataset+provider (`?dataset=` restricts GET to one and targets POST/DELETE) |
| `POST /api/datasets/sync` | admin JWT | force a sync/reload (`?dataset=`; `&provider=` for one provider) |
| `GET/POST/DELETE /api/ja4providers` | JWT / admin write | alias of `/api/datasets` pinned to the `ja4` dataset (legacy) |
| `POST /api/ja4providers/sync` | admin JWT | alias of `/api/datasets/sync` for `ja4` (legacy) |
| `GET /api/stats` | JWT | `{users,queries_total,queries_today}` for the dashboard |
| `GET /api/logs?limit=N` | JWT | recent query history (default 50, max 500) |
| `GET/POST/DELETE /api/ipproviders` | JWT / admin write | IP lookup chain (list, add/update, delete) |
| `POST /api/ipproviders/test` | admin JWT | query one IP through the lookup chain |
| `GET/POST /api/ip/lookup` | JWT | look up IPs the caller names (`?ip=`, `&nocache=1`, or `{"ips":[…]}`, max 100); one address returns the bare IP object |
| `POST /api/ip/lookup/bulk` | JWT | plain-text batch (one address per line or comma separated), same response shape |
| `GET /api/ip/history?ip=` | JWT | whether/how that IP called `/echo`, from the query log |
| `GET /api/logs` | JWT | filtered history (`limit/method/country/type/ip/q/days`) |
| `GET /api/audit`, `/api/audit/export.csv` | JWT | audit trail (`limit/action/username`, CSV export) |
| `GET/POST/DELETE /api/notifications` | JWT | list/unread count, mark one/all read, cleanup |
| `GET/POST/DELETE /api/views` | JWT | saved query-log filter views |
| `GET/POST/PATCH/DELETE /api/apikeys` | admin JWT | named API keys (`X-API-Key`; plaintext returned once) |
| `GET/POST/PATCH/DELETE /api/webhooks` | admin JWT | signed event delivery |
| `POST /api/webhooks/test` | admin JWT | send a sample event to one webhook |
| `GET /api/system`, `/api/system/environment` | JWT | runtime info / non-secret config view |
| `GET /api/system/backup` | admin JWT | SQLite `VACUUM INTO` download |
| `POST /api/system/purge-logs`, `/api/system/rotate-jwt` | admin JWT | retention purge / rotate signing key |
| `GET /api/metrics/summary?hours=N` | JWT | trend and top-N aggregates |
| `GET /metrics` | — | Prometheus text exposition |
| `GET /api/export/{logs,users}.{csv,json}`, `/api/export/config.json` | JWT / admin | data export (secrets excluded) |
| `POST /api/replay` | admin JWT | re-run a request through the real echo handler |
| `GET /api/ja4/search?q=`, `/api/ja4/stats` | JWT | fingerprint search and provider statistics |
| `GET /api/endpoints` | JWT | endpoint catalogue |
| `GET /api/openapi.json` | — | OpenAPI 3.0.3 document (public, for client generation) |
| `GET /health` | — | liveness |

```bash
# fresh install: create the first admin from the command line (or use /ui/)
JWT=$(curl -sk -X POST https://HOST:8443/api/setup -H 'Content-Type: application/json' \
  -d '{"username":"owner","password":"a-long-password"}' | jq -r .token)

# ...or on an existing install: log in and keep the token
JWT=$(curl -sk -X POST https://HOST:8443/api/login -H 'Content-Type: application/json' \
  -d '{"username":"owner","password":"a-long-password"}' | jq -r .token)

# create a read-only account, then rotate your own password
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass","role":"viewer"}' https://HOST:8443/api/users
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"old_password":"a-long-password","new_password":"a-longer-pass"}' https://HOST:8443/api/me/password

# disable an account (its existing tokens stop working immediately)
curl -k -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"username":"alice","disabled":true}' https://HOST:8443/api/users
```

## IP intelligence

IP location works two ways: `/echo` answers for the caller's own source address, and a dedicated lookup
API answers for **any address the caller names** (`/api/ip/lookup`, console page `/ui/lookup`) — useful for
triaging addresses in logs, abuse reports, or batch enrichment.

```bash
# one address (the single result is the bare IP object)
curl -k -H "Authorization: Bearer $JWT" 'https://HOST:8443/api/ip/lookup?ip=8.8.8.8'

# batch of up to 100 (results keep input order); nocache=1 bypasses the result cache
curl -k -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"ips":["8.8.8.8","1.1.1.1","104.131.0.1"],"nocache":false}' https://HOST:8443/api/ip/lookup

# plain-text batch (one address per line, or comma separated)
printf '8.8.8.8\n1.1.1.1\n' | curl -k -X POST -H "Authorization: Bearer $JWT" \
  --data-binary @- https://HOST:8443/api/ip/lookup/bulk
```

- Offline by default-capable: ~14.8k embedded datacenter prefixes (AWS/GCP/DigitalOcean/Oracle official lists, Akamai's announced prefixes + major hosting brands) and a 100-entry residential-proxy sample — no network needed.
- Online (optional): `ipwho.is` → `ip-api.com` → `ipinfo.io`, cached (`geo_cache_ttl`, default 24h). Failed lookups are not cached, so a transient timeout does not blank an IP for a day.
- Set an **ipinfo token** in the admin UI to use ipinfo's `loc` coordinates and authoritative `proxy/vpn/tor/hosting` labels; ipinfo also supplies an `anycast` flag, which means the city fields are not meaningful.
- Turn online lookups off entirely with *enable online IP intelligence*; failed lookups leave geolocation empty rather than guessing.

### Accuracy and limits

Measured on 2026-11-18 through the running server (`/echo?fields=ip`), on 620 uncached IPs: 500
stratified across the five RIRs (100 each) plus 120 from China. DB-IP City Lite (free monthly)
is the independent reference; ASN and country are cross-checked against Team Cymru. China is also
checked against zxinc's domestic database.

| Field | ipwho.is (default first), n=620 | ip-api.com, n=150 | ipinfo.io (no token), n=150 |
|---|---|---|---|
| Country | 96.6% | 98.6% | 98.7% |
| Region / state | 77.5% | 79.7% | 79.1% |
| City name | 51.6% | 68.1%† | 54.0% |
| City within 25 km | 76.1% (median 6 km) | 75.4%† | 70.7% (median 5 km) |
| ASN (where returned) | 98.6% | 98.2% | 99.1% |
| China province (79 IPs) | 66.2% | — | — |
| China city (46 IPs) | 47.8% | 28.3%* | 37.0% |
| China country (79 IPs) | 98.7% | 97.5% | 98.7% |

† ip-api's city data comes from the same upstream as DB-IP (identical city names and, in this run,
a median coordinate distance of 0 km), so its city/coordinate agreement with DB-IP is circular and
should not be read as independent accuracy.

\* The China city row compares each provider directly with zxinc (the product comparison above
uses the `auto` chain, which usually ends up on ipwho.is). For the 46 IPs where zxinc reports a
city, ip-api's city name matches 28.3%, ipinfo 37.0%, ipwho.is 47.8%.

Provider availability differs materially: ipwho.is answered all 620 IPs, ipinfo 146/150, but
ip-api answered only 66/150 with 81 giving no data at all (the free tier's rate limit drops or
times out requests; 3 more were served by the chain falling back to ipwho.is/ipinfo). The chain
treats a non-answer as "try the next provider", so the default `auto` chain still returns data.

Country-level answers are good enough for analytics and coarse policy; city-level answers are a
hint, not evidence. Do not use them for precise geofencing, fraud decisions, or anything
safety-critical without a commercial database (MaxMind, IPinfo paid, IPIP, etc.) and a review path.

Limitations you should expect:

- **Anycast** (8.8.8.8, 1.1.1.1, CDN edges) has no single city; providers disagree by design. Prefer `anycast: true` from ipinfo and treat city as unknown.
- **VPN / proxy / mobile** locations describe the exit node or carrier gateway, not the human.
- **China** city-level accuracy is materially lower than in North America/Europe with free international APIs (measured 47.8% city / 66.2% province); use a domestic database (IPIP, pconline) or an ipinfo token if China precision matters.
- **X-Forwarded-For is trusted by design** for proxy deployments. Any client can send it, so `ip` is not an authenticated identity. Use the TCP peer (`remote_addr`) when trust matters, or put the service behind a proxy that overwrites the header.
- **Offline `connection_type`** covers 99–100% of AWS/GCP/DigitalOcean/Cloudflare/Oracle/Akamai official prefixes, and a random public-IP sample showed ~0.2% datacenter false positives, but recall on hosting ASNs outside those lists is low (~3%) and the embedded residential-proxy table has only 100 exits, so offline proxy detection is nearly always `unknown`. Keep the tables current with the data-source engine, or use an ipinfo token for privacy labels and `hosting`.
- **Latency**: online lookups run synchronously on the echo path. A cache miss costs the provider's response time (ipwho.is median 365 ms, p90 380 ms in this test); when ipwho.is is unavailable the chain falls through to ip-api (median ~1.2 s, p90 ~4 s at its 4 s timeout). Cached hits are ~5 ms. Keep the chain short if you need a hard latency bound.
- **Cache TTL** (24h default) can delay reassignment changes; `residential_proxy` also covers VPN/Tor exits reported by ipinfo.

## Build & release

The release artifact is one self-contained executable per platform. CI builds the console, GoReleaser
compiles it into the binary, and GitHub Releases carries the archives plus `checksums.txt`.

```bash
make frontend            # npm ci + tsc + vite build -> frontend/dist
make build               # frontend + go build (version/commit/date injected via -ldflags)
make test                # go test ./... -race -count=1
make lint                # fail if a Go file is not gofmt-formatted
make docker              # container image
make snapshot            # cross-compile all release targets locally (goreleaser build --snapshot)
make release-snapshot    # local archives + checksums in dist/ (no publish)
```

Release flow (full checklist: [RELEASING.md](RELEASING.md)):

1. `git tag v1.0.0 && git push origin v1.0.0` — publishes the **full** product.
2. `git tag lite-1.0.0 && git push origin lite-1.0.0` — publishes the **lite** build, as its own
   release, tagged and artifacted separately (`echo-server-lite_*`), so the two never mix.
3. `.github/workflows/release.yml` runs the tests, a live smoke test of the built binary (`/ip`, `/echo`,
   the console page and `/api/login`), then GoReleaser; its `before` hooks build `frontend/dist`.
4. `.github/workflows/release-lite.yml` builds the lite binary, starts it with `ECHO_SERVER_LITE=1` and
   asserts `/ip` works while `/ui` and `/api` answer 404 and no database file appears, then runs
   GoReleaser with `.goreleaser-lite.yaml`.
5. Artifacts: `echo-server_<version>_<os>_<arch>.tar.gz` (zip on Windows) for linux/darwin/windows ×
   amd64/arm64, `checksums.txt`, auto-generated changelog, and a GitHub Release.
6. Version, commit and build date are injected with
   `-X main.serverVersion/buildCommit/buildDate` and shown on `/ui/system` and in `GET /api/system`.
   Source builds report `version: dev`; release binaries always carry the tag.

`.github/workflows/ci.yml` runs on every push to `main`, every PR, and manually: it builds the
frontend, checks `gofmt`, runs `go vet ./...` and `go test ./... -race -count=1`, then builds the
single binary, smoke-tests the embedded UI + injected version from a clean directory, and builds
the Docker image.

## Tests

```bash
go test ./...            # offline-deterministic; online provider tests skip without network
go test ./... -short     # skip all network tests
```

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the build/test workflow and
commit conventions. Security issues must go through the private advisory link in
[SECURITY.md](SECURITY.md), not a public issue.

## License

[MIT](LICENSE) © 2026 crawler-requests
