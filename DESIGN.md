# Echo Server Product Design

## Overview
Echo Server is a self-contained HTTPS service that echoes full request metadata (headers, body, complete TLS ClientHello with raw bytes, JA3), the client's public IP with ASN/organization, high-precision geolocation (country / region / city / postal / latitude / longitude / timezone) and a connection classification (`datacenter` / `residential_proxy` / `unknown`).

The single Go binary embeds a React + Ant Design admin frontend, uses SQLite for persistent configuration, query history and user accounts, supports JWT login (SQLite-backed users with `admin`/`viewer` roles) and optional API token authentication, and lets callers pick the response format (JSON or plain text) and a subset of fields per request.

## Goals
- Single distributable binary (no external dependencies at runtime)
- Complete request/TLS/IP fingerprinting for crawler-requests organization
- High-precision IP geolocation with residential-proxy vs datacenter distinction
- Per-request control of response format and returned fields (bandwidth/perf savings)
- Admin UI for configuration and history inspection without restarting the service
- Self-hosted user accounts with no cleartext passwords and immediate revocation
- Honest data: never invent geolocation when a lookup fails

## Non-Goals
- Fine-grained per-resource permissions (only `admin`/`viewer` today)
- HTTP/2 or QUIC fingerprinting beyond current JA3 support
- Docker / systemd packaging

## Architecture

### Backend (Go)
- `main.go`: HTTPS server with self-signed cert, per-connection ClientHello capture, echoHandler orchestration, admin/echo routing
- `echo.go`: pure `buildEchoResponse`, `extractClientIP`, and the response serializer (`serializeEcho` = format + field filtering)
- `tls_capture.go`: `helloListener` / `helloConn` (fragmentation-safe per-connection capture, multi-record reassembly), `helloSnapshot`, `wrapListener`
- `hello_parse.go`: `parseClientHello` (full extension parsing), `populateClientHelloWith`, `computeJA3` / `ja3FromParsed`, `ja4FromParsed` (JA4 / JA4_r / JA4_o)
- `clientid.go`: client identification — JA4/JA3 fingerprint tables, User-Agent parser, consistency (spoof) check, header-set hash
- `ja4db.go`: embedded JA4DB snapshot (`data/ja4db.json`), per-fingerprint candidate aggregation, exact + prefix lookup, compiled-library type (`ja4Lib`), provider-attributed matches (`source: "ja4db:<provider>"`)
- `datasets/engine.go`: **generic data-source engine** — a `Dataset` is assembled from priority-ordered providers of four kinds (`embedded` / `file` / `remote` / `command`); generic `Codec` decides decode + merge; immutable runtime value published via `atomic.Pointer` (lock-free query path); fetches/decodes run outside the lock with generation-checked publish; on-disk cache + persisted `ETag` + `If-None-Match` re-sync for refreshable kinds; mtime watch for `file` providers; request `headers` (masked in status) for private clouds; `RegisterScheme` extension point for custom URL transports; per-dataset persistence delegated to the host via `Saver`/`LoadConfig`
- `dataset_ja4.go` / `dataset_ipclass.go` / `datasets_api.go`: the `ja4`, `datacenter_cidr`, `residential_proxy_cidr`, `datacenter_orgs` datasets (each with embedded `builtin` defaults); generic `/api/datasets` API; legacy `/api/ja4providers` aliases
- `ja4h.go`: JA4H HTTP-layer fingerprint (FoxIO spec, with the sorted-header deviation documented above)
- `ip_classify.go`: `classifyIP` delegates to `ipclass.Classify`
- `ipclass/classify.go`: embedded positive CIDR tables (`data/datacenter_ranges.csv`, `data/residential_proxy_ranges.csv`) + `OrgLooksDatacenter` ASN/org heuristic; runtime range/keyword overrides so datasets drive classification without touching the package
- `ip_geo.go`: multi-provider IP intel (ipwho.is → ip-api.com → ipinfo.io), TTL memory cache, provider normalization, classification finalization
- `storage.go`: SQLite abstraction (`~/.echo-server/echo.db`, overridable via `ECHO_SERVER_DB`) with `config`, `query_log` and `users` tables
- `users.go`: user accounts — PBKDF2-SHA256 (210k iterations, random salt) password hashes, `admin`/`viewer` roles, enable/disable, last-login tracking, first-run setup (`CreateFirstAdmin`, only while the table is empty, always admin; no default password; headless bootstrap via `ECHO_SERVER_ADMIN_USERNAME`/`ECHO_SERVER_ADMIN_PASSWORD`), optional self-registration (viewer-only), last-enabled-admin protection
- `users_api.go`: account API (`/api/setup`, `/api/setup/status`, `/api/register`, `/api/users`, `/api/me`, `/api/me/password`)
- `auth.go`: JWT (HS256, 12h) for SQLite accounts + API token; the signing key comes from `ECHO_SERVER_JWT_SECRET` or is generated once and persisted (`jwt_secret`), with `rotateJWTSecret()` behind a mutex; every authenticated request re-reads the account so disabled/deleted users and role changes take effect immediately; a missing/invalid Bearer token falls back to `X-API-Key`; `adminMiddleware` gates account management
- `apikeys.go`: named API keys (`esk_…` plaintext returned once, SHA-256 stored, scope viewer/admin, optional expiry, async `last_used`) and webhooks (event subscriptions, per-hook secret, async HMAC-SHA256 signed delivery, failure notifications)
- `admin_audit.go`: lazily-created `audit_log` / `notifications` / `saved_views` tables; `RecordAudit` (auto-generates notifications for `user.*`/`security.*`/`config.*`/`system.*`), audit listing + CSV export, notification list/mark-read/cleanup, saved log views
- `security.go`: `securityMiddleware` — security headers, CORS, IP allow/deny rules (IP or CIDR) restricted to echo traffic, per-IP per-minute rate limiting, maintenance mode (503 for unauthenticated echo), request body cap; background worker purges logs by `log_retention_days` every 6 hours and trims notifications to 500
- `system.go`: runtime info (`/api/system`), non-secret environment, `VACUUM INTO` backup download, log purge, JWT rotation
- `metrics.go`: `/api/metrics/summary` (hourly gap-filled series, top IPs/countries/methods/connection types) and `/metrics` Prometheus exposition
- `export.go`: shared log filter/parse/fetch (used by `/api/logs`), CSV/JSON exports for logs/users/config (secrets excluded), request replay entry point
- `replay.go`: `replayEcho` runs the real `echoHandler` via `httptest` in-process; replays are marked in the context and skip `LogQuery`
- `ja4_api.go`: `/api/ja4/search` (exact fingerprint / client-name search across providers) and `/api/ja4/stats`
- `apidocs.go`: endpoint catalogue (~55 entries) and generated OpenAPI 3.0.3 with Bearer + API-key schemes

### ClientHello capture (per connection, fragmentation-safe)
`wrapListener` wraps the TCP listener; each accepted connection becomes a `helloConn` that captures the ClientHello **before** the TLS handshake consumes it. `http.Server.ConnContext` unwraps the `*tls.Conn` via `NetConn()` and stores the `helloConn` in the request context, so every request echoes **its own** ClientHello — never a shared global (which cross-contaminates across connections). A global remains only as a fallback for tests.

Capture is incremental, not one-shot. TCP does not preserve TLS record boundaries: `crypto/tls` first reads the 5-byte record header and then the body, and a large hello (Go 1.24+ post-quantum `X25519MLKEM768` → ~1.5 KB record) can arrive in many reads. `helloConn.Read` therefore appends every chunk to a per-connection buffer and parses forward: it stitches TLS handshake records (type 0x16) back together until a complete ClientHello handshake message is available. Bounds: 64 KB buffered, at most 16 records; anything else (non-TLS, oversized garbage) gives up without storing a partial hello. This is what makes capture work under byte-level fragmentation — a naive "first read must contain the whole record" check never fires, because the header and body are separate reads.

Exposed fields (`client_hello`):
| Field | Meaning |
|---|---|
| `raw_base64` | ClientHello handshake message, base64 (encoded exactly once) |
| `raw_hex` | same bytes, hex |
| `raw_record_base64` | all carrying TLS records, including their 5-byte headers, concatenated |
| `length` | handshake message length (header included) |
| `record_length` / `record_count` / `record_version` | total record bytes / number of records spanned / first record's version field |
| `version`, `cipher_suites`, `extensions`, `compression_methods` | parsed fields |
| `sni` | server_name from extension 0x0000 |
| `alpn` | ALPN protocol list from extension 0x0010 |
| `supported_versions` / `signature_algorithms` / `supported_groups` / `key_share_groups` | extension 0x002b / 0x000d / 0x000a / 0x0033 |
| `has_grease` / `ech` | GREASE identifiers present / ECH extension (0xfe0d) present |
| `ja3`, `ja3_hash` | JA3 string (wire order, GREASE kept) and its **real MD5** hash |
| `ja4`, `ja4_r`, `ja4_o` | JA4 per the FoxIO spec: GREASE removed, ciphers/extensions sorted and hashed (`ja4`), sorted raw values (`ja4_r`), original order with SNI/ALPN retained (`ja4_o`) |

`tls` mirrors `ja3_string` / `ja3_hash` / `ja4` / `ja4_r` / `ja4_o` plus negotiated `tls_version` / `cipher_suite` / `server_name` / `alpn` / `resumed`.

Parsing lives in `hello_parse.go` (`parseClientHello`, `populateClientHelloWith`, `ja3FromParsed`, `ja4FromParsed`); capture lives in `tls_capture.go`.

### Client identification (`client`)
Answers "which client is this?" by combining signals, weighted by how hard each is to forge:

1. **Fingerprint providers (trust anchor, largest)** — the `ja4` dataset maps the ClientHello to the clients
   observed sending it. It uses the same generic data-source engine as every other data set: priority-ordered
   providers, the embedded JA4DB snapshot always last. Exact-JA4 first, then a JA4 prefix (head + cipher hash)
   for builds newer than a library, walking providers from highest priority to lowest; the first provider that
   knows the fingerprint wins.
   - `builtin` (embedded, always last) — the frozen JA4DB public-API snapshot (ja4db.com; now closed, mirrored
     at github.com/Niicolaa/ja4db-export): 1,572 fingerprints / ~74k observations, compacted by
     `tools/ja4dbgen` into `data/ja4db.json` (~600 KB, embedded).
   - `file` (local) — operator-supplied JSON (the same contract) or community CSV (`ja4_fingerprint.csv`,
     imported with the generator's aggregation rules); a **directory** provider merges every decodable file.
   - `remote` (cloud) — the same JSON contract fetched over HTTPS (or any `RegisterScheme` scheme), cached on
     disk (survives restarts), re-synced with `If-None-Match` and an optional interval. This is the
     cloud-database client for private deployments: cloud → disk cache → embedded snapshot on failure.
   - `command` — stdout of a shell command is the data; lets an operator implement a fingerprint source in any
     language, refreshed on an interval.

   Each fingerprint resolves to weighted client candidates; shared fingerprints (Go 1.24+ and Chrome both
   send the post-quantum key share; crawlers submit spoofed Chrome UAs) surface as `candidates` + a note
   rather than a false certainty. A custom provider's verdict is attributable: `source: "ja4db:<provider>"`.
2. **TLS table** — exact JA4, then exact JA3 hash, then family heuristics (GREASE ⇒ browser TLS;
   X25519MLKEM768 key share ⇒ Go 1.24+; FFDHE groups ⇒ Java; the Node extension set). Entries were measured from
   real clients against this server: curl, wget (GnuTLS), python-requests, Node.js, Java 21, OpenSSL, Go net/http,
   Chromium. A measured fingerprint that JA4DB cannot name (or shares with others) is reported with the database's
   context.
3. **User-Agent** — a compact parser for curl / wget / python-requests / aiohttp / httpx / node-fetch / okhttp /
   Postman / Java / Go-http-client / Chrome / Edge / Opera / Firefox / Safari / HeadlessChrome / Googlebot &
   friends, returning name, family, version. When TLS and the UA name the same client, the UA's concrete version
   is reported (the JA4DB range describes other people's builds).
4. **Header set** — `header_set_hash` (canonical, order-independent; Go's `http.Header` is a map so wire order is
   not recoverable server-side) plus a "looks browser-like" hint (rich `sec-*` / `accept-*` set).

`family` is one of `browser | cli | library | runtime | tool | bot | http_client | unknown`. When the two sides
disagree in a way real clients never do — e.g. a Go/OpenSSL handshake carrying a Chrome UA — the request is marked
`spoofed: true`, the **TLS side is reported as the identity**, and the note states both the truth and the claim. A
browser-family mismatch in either direction counts as spoofing; cli/library/http_client overlap is legitimate
(curl, python and wget share crypto stacks).

```json
"client": {
  "name": "curl", "family": "cli", "version": "8.5.0", "confidence": 0.95,
  "signal": "user_agent", "source": "user_agent",
  "matches": ["JA4 exact match: t13i3111h2_…", "User-Agent: curl/8.5.0", "TLS family and User-Agent agree"],
  "spoofed": true,
  "candidates": [{"name": "Chrome", "family": "browser", "share": 0.69}],
  "db_observations": 587,
  "notes": ["… shared fingerprint …", "TLS fingerprint says … the UA is very likely spoofed"],
  "header_set_hash": "a1b2c3d4e5f6"
}
```

`source` states which layer named the client (`ja4db`, `ja4db_prefix`, `ja4db:<provider>`, `ja4_measured`,
`ja3_measured`, `user_agent`, `ja4_heuristic`). Controlled by the `show_client` config key (default on).

Provider management is generic: `GET/POST/DELETE /api/datasets` (or the dataset-scoped
`POST /api/datasets/sync`) with JWT, persisted per dataset in the SQLite config key `dataset_providers:<name>`,
seeded at startup from the `DATASET_PROVIDERS` environment variable (JSON object keyed by dataset name). The
legacy `/api/ja4providers` endpoints and `JA4_PROVIDERS` env / `ja4_providers` config key remain as aliases for
the `ja4` dataset. Each dataset's runtime value is an immutable structure published through an atomic pointer,
so the request path never takes a lock.

Refreshes run **outside the manager lock**: `refresh` snapshots the config under the lock, fetches/executes and
decodes with the lock released, then re-acquires it to publish. A generation counter discards a result whose
provider was reconfigured or deleted while the fetch was in flight, and a sync sequence clears the in-flight flag
only for the latest attempt, so a slow cloud never stalls status/API calls or blocks a new configuration.

Scheduling: `file` providers with `refresh_min > 0` are watched by modification time (directory = newest
non-hidden child) and reloaded atomically on change; `remote`/`command` providers refresh on their interval
(at most one per minute tick, and once at startup when due). `refresh_min = 0` means manual only. `POST
/api/datasets/sync` forces a refresh, and re-reads a `file` provider unconditionally. Refreshable payloads are
cached on disk together with the HTTP `ETag`, so a restart revalidates with `If-None-Match` instead of
re-downloading, and a failed refresh keeps the last good value in effect. `datasets.RegisterScheme` lets
embedders add URL transports (`s3://`, `gs://`, an internal artifact store, …) usable by any `remote` provider —
the extension surface for user-defined data sources.

Credentials: a `remote` provider may carry `headers` (e.g. `Authorization` for a private cloud) and URL
userinfo (sent as Basic auth). Every status/list response masks those values (`***`); posting the mask back
keeps the stored secret, so editing other fields does not require retyping a token.

### JA4H (HTTP-layer fingerprint, `ja4h`)
The FoxIO HTTP companion to JA4: 2-char method, 2-digit HTTP version, c/n for cookies, r/n for referer, 2-digit
header count, 4-char Accept-Language, then 12-hex hashes of the header-name set, the cookie-field names and the
cookie values. It separates clients that share one TLS stack at the HTTP layer and cannot be changed by editing
the User-Agent alone. Deviations from the reference, both forced by Go's `http.Server` (the wire is already
consumed): header names are **sorted** before hashing, and `Host` is not counted (it lives in `r.Host`, not the
header map). The cookie field/value hashes match the reference byte-for-byte. Implemented in `ja4h.go`, emitted
as the top-level `ja4h` field, controlled by `show_ja4h` (default on).

### IP classification and geolocation
Connection type resolution order:
1. **Local CIDR table** (offline, deterministic): datacenter table (~10k prefixes, AWS/GCP/DigitalOcean official ranges + Cloudflare/Hetzner/OVH/Fastly/Akamai/Oracle/etc.) → `datacenter`; residential-proxy sample set → `residential_proxy`; datacenter wins on overlap.
2. **Authoritative privacy labels** (only when an ipinfo token is configured): `proxy`/`vpn`/`tor` → `residential_proxy`, `hosting` → `datacenter`.
3. **ASN/org heuristic**: if still `unknown` and the org name matches a hosting/cloud brand (Amazon, Microsoft, Google, DigitalOcean, Hetzner, …) → `datacenter`.

A public IP matching none of these is `unknown` — a missing datacenter match is **not** evidence of residential use.

Geolocation/ASN/privacy answers come from a **lookup chain** (`iplookup/`), an ordered list of query providers
tried one IP at a time:

- `builtin`: Go drivers compiled into the host (`ipwhois`, `ipapi`, `ipinfo`), registered with `RegisterDriver`.
- `http`: any cloud API URL template containing `{ip}` (escaped) or `{ip_raw}` (verbatim), plus optional
  `headers` and a field `mapping`.
- `command`: `sh -c` with `{ip}` substituted; stdout must be JSON (optionally mapped).

Providers are sorted by effective priority (`Rank` may override at lookup time — a configured `ipinfo_token`
boosts the `ipinfo` built-in to 1000). The first provider returning usable data wins; failures, rate limits and
empty answers are recorded per provider and hand over to the next link. A `Gate` applies global switches at
lookup time without rewriting stored config: `enable_online_geo=false` blocks every link, and a specific
`geo_provider` keeps only that built-in driver (operator-added providers still participate). Built-ins ship at
priorities `ipwhois=20`, `ipapi=10`, `ipinfo=5`.

The normalized `Info` (country/country_code/region/city/postal/timezone/UTC offset/continent/lat/lon, ASN,
ASN name, org, ISP, and `is_proxy`/`is_vpn`/`is_tor`/`is_hosting`) is accepted as-is; any other JSON shape is
described with `mapping` of Info field → dot path (array indices supported), so a new cloud API needs no Go code.
Per-provider stats (calls/successes/failures/average latency/last error/last success) drive the admin table and
make silent degradation visible. Providers are persisted in SQLite `ip_lookup_providers` and can be seeded with
`IP_LOOKUP_PROVIDERS` (JSON array, applied after the persisted list); credentials in `headers`/URL userinfo are
masked in every status response and `***` posted back keeps the stored value. Built-ins cannot be deleted, only
disabled or re-prioritized. The test endpoint `POST /api/ipproviders/test` queries one IP through the chain,
bypassing the result cache.

Results are cached in memory with a configurable TTL (`geo_cache_ttl`, default 24h) and a bounded size (4096
entries). Private/loopback addresses never trigger lookups. When no provider answers, geolocation fields are
**left empty** and `geo_source="local"` — the server does not fabricate coordinates.

### Per-request response control
Two independent knobs, resolved as **query parameter > request header > admin default**:

| Control | Query | Header | Values |
|---|---|---|---|
| Format | `format` | `X-Echo-Format` | `json` (default) / `text` |
| Fields | `fields` | `X-Echo-Fields` | comma-separated dot paths, e.g. `ip.country,ip.latitude,client_hello.sni` |

- No `fields` ⇒ full response.
- `fields` narrows to exactly the requested paths; unknown paths are ignored; selecting a parent (`ip`) returns the whole object.
- Text output is deterministic `key=value` lines, nested objects flattened with dot paths (`ip.country=United States`), headers flattened as `headers.<Name>=["value"]`. Strings print verbatim; arrays/numbers/booleans print as compact JSON.
- Admin visibility toggles (`show_*`) are applied **before** serialization, so a request can narrow but never widen what the operator exposes.

### Config keys (SQLite `config` table)
| Key | Default | Meaning |
|---|---|---|
| `show_ja3` | true | include JA3 in responses |
| `show_ip` | true | include the `ip` object |
| `show_raw` | true | include raw ClientHello bytes (base64/hex) |
| `show_body` | true | include the request body |
| `show_client` | true | include the `client` identification block |
| `show_ja4h` | true | include the `ja4h` HTTP-layer fingerprint |
| `require_token` | false | echo endpoint requires JWT or API token |
| `allow_registration` | false | expose public self-registration; new accounts are always viewers |
| `api_token` | (empty) | shared token accepted via `X-API-Token` or `?token=` |
| `enable_online_geo` | true | allow outbound IP-intel lookups |
| `geo_provider` | auto | `auto` / `ipwhois` / `ipapi` / `ipinfo` / `offline` |
| `geo_cache_ttl` | 24 | cache TTL in hours |
| `ipinfo_token` | (empty) | enables street-level geolocation + privacy labels; also boosts the `ipinfo` chain link |
| `ip_lookup_providers` | built-ins | JSON array of the IP lookup chain (built-in/HTTP/command providers, order and stats; managed by the admin UI/API or `IP_LOOKUP_PROVIDERS`) |
| `default_format` | json | fallback format when the request specifies none |
| `dataset_providers:<name>` | (empty) | JSON array of custom providers per dataset (managed by the admin UI/API; `ja4`, `datacenter_cidr`, `residential_proxy_cidr`, `datacenter_orgs`) |
| `ja4_providers` | (empty) | legacy alias of `dataset_providers:ja4` |
| `jwt_secret` | generated | internal HS256 signing key for console sessions (not exposed by `GET /api/config`; override with `ECHO_SERVER_JWT_SECRET`) |
| `site_name` / `site_description` | empty | console branding (site name also drives `document.title`) |
| `timezone` / `locale` / `density` | Asia/Shanghai / zh-CN / default | UI preferences |
| `ip_allowlist` / `ip_denylist` | empty | IP/CIDR rules for echo traffic (deny wins; empty allowlist = allow all) |
| `rate_limit_per_min` | 0 | per-IP per-minute cap on echo traffic (0 = off) |
| `body_limit_kb` | 0 | echo request body cap (0 = off; over-limit returns 413) |
| `cors_origins` | empty | comma-separated allowed origins; unset keeps the legacy `*` echo behavior |
| `security_headers` | true | extended security headers (`false` keeps only the baseline set) |
| `maintenance_mode` / `maintenance_message` | false / empty | unauthenticated echo returns 503 while the console/API stay up |
| `log_retention_days` | 0 | background purge of query logs (0 = keep forever) |

### Frontend (TypeScript + React + Ant Design)
- Embedded via `//go:embed frontend/dist`, served at `/ui/`; `newSPAHandler` falls back to `index.html` for extension-less client routes (`/ui/users`, `/ui/logs`) while missing assets still return 404
- Vite `base: '/ui/'` so built asset URLs resolve under the console prefix
- Shell: collapsible desktop sidebar + mobile drawer, sticky header with page title/role/user menu, `BrowserRouter` with `basename="/ui"`; pages receive the session through the router outlet (`useSession`)
- Auth: `GET /api/setup/status` decides between the first-run admin wizard and the login form; `POST /api/setup` creates the first admin (only while no accounts exist), `POST /api/login` {username, password} → {token, user}, and `POST /api/register` appears only when an admin enabled `allow_registration` (always creates a viewer). Authenticated routes require `Authorization: Bearer <jwt>`; `GET /api/me` resolves the account and role on load and logs the console out when the token is no longer valid
- `GET/POST /api/config` — all keys above (`api_token` is masked as `***` for viewers); `GET /api/stats` — dashboard counters; `GET /api/logs?limit=N` — recent query history (max 500)
- Pages: **概览** (stats, 24h trend, latest notifications, quick actions, recent requests, provider health),
  **回显设置** (field matrix, live response preview, per-request controls, presets), **IP 情报** (provider
  health, chain test, field and privacy reference), **数据源** (cross-dataset stats, per-dataset provider tabs,
  merge order and format reference), **IP 查询链路** (chain stats and order, priority/enable toggles,
  per-provider stats, per-IP test, normalization fields, config samples), **JA4 指纹库** (search, candidates,
  provider health), **监控分析**, **查询日志** (quick presets, 24h trend, top IP/country, server-side filters,
  exports, saved views, detail drawer, replay), **审计日志** (stats, distributions, detail drawer, action
  dictionary), **通知中心** (stats, filters, source distribution, lifecycle), **用户管理** (admin only: stats,
  filters, permission matrix, activity, onboarding), **访问控制** (token strength, endpoint auth matrix, code
  samples, checks), **安全与防护** (overview score/checklist, API keys, auth precedence, IP rules, rate limit,
  body cap, CORS, headers, maintenance, retention, backup, JWT rotation), **集成与 Webhook** (admin only: event
  catalogue, delivery log, signature samples), **系统设置**, **API 文档**, **工具箱** (grouped network/codec/
  security/HTTP tabs, 18 tools), **我的账户** (JWT countdown, password strength, personal audit trail)
- Shell: grouped sidebar, mobile drawer, header bell with unread badge (60s refresh), `Ctrl/⌘+K` command palette,
  site name from `/api/config` applied to `document.title`
- Shared UI pieces: `PageHeader`, `MiniChart` (dependency-free SVG area/line chart), local tool implementations in
  the toolbox (CIDR, base conversion, URL parser, special ranges, SHA/HMAC, Base64, URL, JSON, timestamps, tokens,
  JWT, UUID, password strength, curl, UA, HTTP status, regex)

### Listeners
- `PORT` (default `8443`): HTTPS with per-connection ClientHello/JA3/JA4 capture; serves the full mux (echo, UI, APIs).
- `HTTP_PORT` (default `8080`, `0`/`off` disables): plain HTTP serving the same mux. This is the default console entry point because a self-signed certificate otherwise blocks the browser; HTTP requests have no `tls` object and no ClientHello, so TLS fingerprint fields are empty there. TLS fingerprinting still requires the HTTPS listener.

### Data Flow
0. Startup: `initAllDatasets` builds every dataset — embedded defaults attached, custom providers restored from
   SQLite `dataset_providers:<name>` (plus env `DATASET_PROVIDERS` / legacy `JA4_PROVIDERS`) — and each manager
   compiles an immutable runtime value; refreshable providers load their disk cache (and persisted `ETag`)
   immediately and then sync in the background (startup + interval-driven), while watched file providers are
   re-read whenever their modification time moves
1. Client connects; `helloConn` captures the ClientHello; `ConnContext` binds it to the request
2. `echoHandler` builds the response, parses the connection-bound ClientHello + JA3
3. `fetchIPInfo` → cache → provider lookup → classification finalization
4. `LogQuery` records {ts, method, path, ip, connection_type, country}
5. Admin `show_*` toggles applied → `serializeEcho(format, fields)` → JSON or text

## Security
- Passwords are never stored or returned in cleartext: PBKDF2-SHA256, 210k iterations, a 16-byte random salt per password, self-describing `pbkdf2-sha256$iter$salt$key` format, constant-time verification. Login answers with a generic `invalid username or password`.
- The JWT signing key is `ECHO_SERVER_JWT_SECRET` when set, otherwise a random 24-byte key generated once and persisted in SQLite (`jwt_secret`). Tokens are HS256-only with a 12h expiry; a restart does not invalidate existing sessions.
- Every authenticated request re-reads the account from SQLite, so disabling, deleting, or demoting a user takes effect immediately — no waiting for the token to expire. The role used for authorization also comes from the database, not from the token.
- A fresh installation ships **no default account**: `POST /api/setup` (and the `/ui/` wizard) creates the first account, always with the `admin` role, and is rejected with 409 once any account exists. Headless deployments can instead set `ECHO_SERVER_ADMIN_USERNAME` + `ECHO_SERVER_ADMIN_PASSWORD` for the first start. Self-registration is off unless an admin enables `allow_registration`; `POST /api/register` then creates viewers only (role in the request is ignored) and can never create the first account. Account management and every mutating endpoint (config, datasets, IP-chain) require the `admin` role; `viewer` accounts pass only GET/HEAD (`adminWriteMiddleware`), so the read-only role is enforced by the server, not just hidden in the UI. The last enabled admin cannot be deleted, disabled or demoted, and an admin cannot delete or disable their own account.
- When `require_token=true`, the echo endpoint requires a valid JWT for an enabled user or the configured API token.
- Named API keys are stored as SHA-256 only; the `esk_…` plaintext is shown once at creation. Each key carries a scope and optional expiry; disabling/deleting a key revokes it immediately. `X-API-Key` is honored only when no valid Bearer JWT is present, so a user token always takes precedence.
- `securityMiddleware` wraps both listeners. IP allow/deny rules, the per-IP rate limit, maintenance mode and the body cap apply to **echo traffic only** (`/api`, `/ui`, `/health`, `/metrics` are excluded), so an operator cannot lock themselves out of the console with an IP rule or maintenance switch. Deny rules win; an empty allowlist means allow all; invalid entries are ignored at parse time.
- Baseline security headers (`X-Content-Type-Options`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy`) are always sent; `security_headers=true` adds XSS/Permissions-Policy/COOP hardening. CORS uses `cors_origins` when set and otherwise keeps the legacy `*` echo behavior.
- Every mutating admin action is recorded in `audit_log` (actor, action, target, detail, IP, ts) and selected prefixes also raise in-app notifications. Webhook deliveries are HMAC-SHA256 signed and asynchronous; a failing endpoint only produces a warning notification, never blocks the request.
- IP-intel lookups send only the client IP to the chosen third-party provider; `offline` disables them entirely.
- The first-run setup endpoint is necessarily public: while the users table is empty, whoever can reach the port can claim the first admin. Finish initialization immediately after installing, or pre-seed the admin with `ECHO_SERVER_ADMIN_USERNAME`/`ECHO_SERVER_ADMIN_PASSWORD` before exposing the port.
- Known gaps: login/setup/registration are not rate-limited; webhooks accept arbitrary URLs (an admin-only SSRF vector on a compromised admin account); the audit table is not auto-purged. Put the console behind a trusted network or a reverse proxy with rate limiting if it is internet-facing.

## Storage Location
`~/.echo-server/echo.db` (0700 directory), overridable with `ECHO_SERVER_DB` (tests use a temp DB).

## Build & Release
- **Single artifact**: `main.go` embeds `frontend/dist` with `//go:embed`, so the Go executable contains the
  console, its assets and the embedded datasets. Deploying means copying one file; no Node runtime, static
  directory or sidecar process is needed at runtime.
- **Build order matters**: `frontend/dist` must exist before `go build` (the `Makefile`'s `frontend` target runs
  `npm ci && npm run build`; CI and GoReleaser run the same commands as `before` hooks). `frontend/dist` and
  `dist/` are gitignored — a clean checkout always rebuilds the UI rather than embedding a stale copy.
- **Version injection**: `serverVersion`, `buildCommit` and `buildDate` are package variables overridden with
  `-X main.*` ldflags at release time and exposed by `GET /api/system` (and the 系统设置 page).
- **GoReleaser** (`.goreleaser.yaml`): CGO-disabled, `-trimpath`, `-s -w`, linux/darwin/windows × amd64/arm64,
  tar.gz (zip on Windows), `checksums.txt`, changelog filtered to user-visible commits. `goreleaser release
  --snapshot` validates the whole pipeline locally without publishing.
- **CI/CD** (`.github/workflows/`): `ci.yml` builds the frontend then runs `go vet` and `go test -race` on every
  push to `main` and every PR; `release.yml` triggers on `v*` tags, runs GoReleaser and publishes the GitHub
  Release.

## Testing Strategy
- Unit tests drive shipped functions only: `ipclass.Classify`, `classifyIP`, `fetchIPInfo`, `echoHandler`, `rootHandler`, `serializeEcho`, `helloConn`, `parseClientHello`, `populateClientHelloWith`
- IP-intel tests run **offline** (`enable_online_geo=false`) for determinism; online provider tests skip when the network is unavailable
- `TestHelloConn_*` proves per-connection capture, reassembly of a hello split across reads/records (including one byte at a time), and that non-TLS/oversized input is ignored
- `TestJA3_*` / `TestJA4_*` check against the published JA3 vector (MD5 `b32309a2…`) and the FoxIO JA4 examples (TLS 1.3/1.2, with/without SNI/ALPN, GREASE removed)
- `TestIdentifyClient_*` runs the measured fingerprints of curl, wget, python-requests, Node, Java, OpenSSL, Go and Chromium through the shipped identifier, plus both spoof directions (Go/OpenSSL TLS with a Chrome UA, browser TLS with a script UA)
- `TestLookupJA4_*` / `TestJA4DB_*` exercise the embedded JA4DB snapshot (exact Chrome resolve, prefix fallback for newer builds, unknown fingerprints, spoofed-against-database verdicts, shared-fingerprint notes)
- `datasets` package tests exercise the generic engine: priority ordering + builtin-last, file and directory providers, disabled-provider exclusion, upsert validation, remote sync with ETag/304, ETag persistence across a restart, on-disk cache survival across a restart (and a dead cloud), command providers, custom URL schemes, stamp/on-change hooks, persistence through the saver, config loading, request-header auth + masking (and masked round-trip), URL-userinfo masking, file/directory mtime hot reload + manual reload, non-blocking refresh under a slow server, and discard of a superseded in-flight refresh
- `TestJA4Dataset_*` / `TestDatasetsAPI_*` exercise the wired datasets: JA4 JSON/CSV file providers overriding the embedded snapshot, remote sync + cache fallback, priority + delete, prefix fallback, env seeding, concurrent lookup against a mutating provider set, the generic `/api/datasets` list/upsert/delete, the legacy `/api/ja4providers` alias, and provider data driving `ipclass` classification (CIDR + residential + org keywords, command providers)
- `TestJA4H_*` pins the JA4H vector against the FoxIO cookie hashes (byte-identical), sorted-header deviation, language/method/version encoding, cookie-order independence, and the handler `show_ja4h` toggle
- `TestSerializeEcho_*` covers JSON/text rendering, field filtering and typos
- `TestRootHandler_RequireToken` covers 401/200 paths
- `TestPasswordHashing`, `TestUserLifecycle`, `TestLastAdminProtection`, `TestLoginAndUserAPI` and `TestBootstrapAdminFromEnv` cover salted hashes and malformed hash rejection, case-insensitive login, create/update/delete, disabled-account login, last-enabled-admin and self-destruction protection, the full login → `/api/me` → self password rotation → admin reset → disable (token revocation) flow, admin-only visibility of `/api/users`, and the env-seeded bootstrap admin
- Live verification: build, start on a port, `curl` for JSON/text/fields, SNI via `--resolve`, Go/curl/OpenSSL clients, a byte-level re-segmenting proxy to force TCP fragmentation, independent Python JA3/JA4 cross-checks, 30-way concurrent connections asserting each response carries its own ClientHello, and an old-vs-new binary comparison (the old implementation loses the hello under fragmentation and reports a previous connection's hello)

## Future Extensions
- HTTP/2 fingerprinting (Akamai) and QUIC/HTTP3
- A hosted shared data service: every dataset's `remote` provider kind is already its client contract (JSON over
  HTTPS, ETag re-sync, disk cache, scheduled refresh) — a cloud server can publish any dataset a private
  deployment mounts
- `datasets.RegisterScheme` transports for object stores (s3://, gs://) and internal artifact repositories
- Grafana dashboard bundle built on the shipped `/metrics` exposition
- Alert rules (threshold-based IP/rate anomalies) delivered through existing webhooks
