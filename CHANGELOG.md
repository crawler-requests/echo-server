# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `anycast` in the normalized IP-intel fields (ipinfo.io supplies it); when true, city/coordinates are not
  meaningful and should not be used for location.
- Oracle's official public IP ranges in the embedded datacenter table (~1.1k prefixes added).
- Akamai's actually-announced IPv4 prefixes (AS20940/16625/32787/21342/36183, merged to 3.6k CIDRs)
  in the embedded datacenter table; the table now holds ~14.8k prefixes.
- **Explicit IP location lookup**: `GET /api/ip/lookup?ip=…` and `POST /api/ip/lookup` (up to 100
  addresses, `nocache` to bypass the result cache), `POST /api/ip/lookup/bulk` (plain-text batch), and
  `GET /api/ip/history?ip=…` (whether that address called `/echo`). A single address returns the bare
  IP object; several return `{count, answered, results}` in input order. Invalid literals, private
  addresses and offline mode explain themselves instead of returning an empty object.
- Console page **IP 定位查询** (`/ui/lookup`): single/batch input, map preview, connection and privacy
  tags, per-IP query-log history.

- **Multi-source JA4 client database**: the embedded library now fuses the JA4DB crowd snapshot
  (~1.6k fingerprints / ~320k submissions) with FoxIO's curated `ja4plus-mapping.csv`. Curated names add
  malware C2 and tunnel fingerprints no submission database carries — Cobalt Strike, Sliver, Qakbot,
  IcedID, Lumma, Pikabot, Darkgate, SoftEther, ngrok — which report `family: "malware"` / `"tunnel"`.
  Matches also carry the OS/library context their submissions recorded (`client.os`, `client.library`,
  `client.fused`). `tools/ja4dbgen` rebuilds both sources in one run and pins the snapshot to its last
  full commit (the moving `@main` ref now serves a truncated file).
- **Client identification is persisted**: `query_log` stores `client_name`, `client_family`,
  `client_source`, `ja4`, `ja3`, `user_agent` and `spoofed` for every echo request, so the log page can
  filter by client family / spoof state / fingerprint and the metrics summary reports `top_clients`,
  `by_family`, `top_ja4`, `spoofed` and `unnamed`. New indexes cover those columns.
- **HTTP/2 fingerprint** (`http2` in the echo response): SETTINGS ids/values in wire order, rep PRIORITY
  frames, and this request's pseudo-header order, rendered in the Akamai `SETTINGS|PRIORITY|PSEUDO`
  format. The server now advertises `h2` in ALPN and runs `golang.org/x/net/http2` itself so the frames
  Go's `net/http` discards can be recorded (`enable_http2=false` pins HTTP/1.1-only).
- GitHub repo badge in the console header (links to the repository, shows its star count). The star
  count is cached for 30 minutes server-side and in the browser, and a failed fetch keeps the last
  value; the repo is configurable with `github_repo`.
- SQLite indexes for the hot query shapes: `query_log(ts)`, `query_log(ip)`,
  `query_log(connection_type, country)`, `audit_log(username)`, `audit_log(action)`,
  `notifications(read, ts)`, `api_keys(key_hash)`, `webhooks(enabled)`, `saved_views(page)`.
- The console bundle is split: pages load lazily per route and the vendor stack is a separate
  cacheable chunk (first load drops from 1421 KB / 447 KB gzip to 821 KB / 262 KB gzip).
- `redact_sensitive_headers` (default on): the echo response masks `Authorization`, `Cookie`,
  `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`, `X-Api-Token`, `X-Auth-Token` and `X-Csrf-Token`
  values (`Bearer ***` keeps the scheme). Turn it off only when debugging token handling.
- Graceful shutdown on `SIGINT`/`SIGTERM`: stop accepting, drain in-flight requests for up to 15s,
  close SQLite, then exit. Previously the process died immediately on signal.
- Login / setup / register are throttled per TCP peer (10 failures or 30 attempts per 15 min),
  independent of the echo limiter and immune to `X-Forwarded-For` rotation.

- **Lite build** (`ECHO_SERVER_LITE=1`): runs with no database at all — no SQLite, no users, no datasets,
  no admin API, no query log. Serves `/ip`, `/echo`, `/health` and `/metrics`; everything else answers
  404. Published as its own release (tag `lite-v*`, `.goreleaser-lite.yaml`) so the artifacts never mix
  with the full product. Verified at **100,000 concurrent connections, 0 failures, 230k+ rps, ~713 MB RSS**
  on a 32-core host.
- **README**: copy-paste prompts for AI agents (Claude Code / Codex / any shell agent) that install,
  start, test and audit the service, each with explicit acceptance tests; English and 简体中文 kept in
  sync, English is the default.
- **Release pipeline**: the full release now smoke-tests the built binary (`/ip`, `/echo`, console page,
  `/api/login`) before publishing; CI gained a lite-mode smoke test (no database, `/ui` and `/api` 404).

### Performance

- **`GET /ip` fast path**: returns only the caller's egress IP (`{"ip":"…"}` or `?format=text` for the
  bare address), skipping TLS parsing, fingerprinting, geolocation and the query log. Measured 127k rps
  at 1,000 connections (plain HTTP, loopback) versus 6.8k for the full `/echo` before tuning.
- **Config values are cached in memory.** `GetConfig` used to be a SQLite SELECT on every call — the
  echo handler reads ~15 keys per request — which capped `/echo` throughput at ~1.3k rps.
- **Query-log writes are batched** into 256-row transactions by one writer goroutine instead of a
  synchronous insert per request; the request path never blocks on disk.
- **Per-request access logging is opt-in** (`access_log=true`); it was writing tens of MB to stderr per
  minute under load.
- HTTP server timeouts (`ReadHeaderTimeout`, `IdleTimeout`, `MaxHeaderBytes`) and SQLite
  `journal_mode=WAL` + `busy_timeout` + a bounded pool.

### Fixed

- Echo rate limiting and IP allow/deny rules now charge the TCP peer bucket as well as the claimed
  client address, so rotating a spoofed `X-Forwarded-For` no longer bypasses the limiter or the
  allowlist.
- The echo body is capped at 8 MB even when `body_limit_kb` is left at 0 (previously unbounded:
  the handler reads the whole body into memory).
- The embedded datacenter table no longer contains a `23.0.0.0/8` entry. That single prefix classified
  every address in 23.0.0.0/8 as `datacenter`, including AT&T, Comcast, Charter, TELUS and Ooredoo
  consumer lines; it is replaced with Akamai's announced prefixes.
- Carrier-operated AWS Wavelength blocks (Verizon/BT/... subscriber space) and AWS China blocks
  (routed to China Mobile/Unicom/Telecom subscribers) are excluded from the datacenter table, so
  carrier traffic is not mislabelled as hosting.
- The `colo` org keyword was tightened to `colocation`: `colo` matched ordinary street addresses such
  as ipwho.is's `org` field "234, Galle Road, Colombo 4", mislabelling a Sri Lankan mobile carrier
  as a datacenter.

- A failed online lookup is no longer cached for `geo_cache_ttl`; a transient timeout/rate-limit cannot blank
  an IP's geolocation for 24 hours.
- ipinfo.io's two-letter `country` is now normalized to an English country name, matching the other providers;
  `country_code` stays the ISO alpha-2 code.
- Documentation no longer claims high-precision/street-level accuracy: measured accuracy and limits are
  documented, with city-level results explicitly marked as best-effort.

## [1.0.0] - 2026-11-12

First public release. One self-contained Go binary with the React console embedded via
`//go:embed`, published for linux/darwin/windows on amd64/arm64.

### Added

- **Echo endpoint** — reflects method, path, headers, body, HTTP version, TLS metadata, client IP and
  geolocation; per-request `format` (`json`/`text`) and `fields` selection via query or header;
  admin-configurable `show_*` field switches.
- **TLS ClientHello capture** — per-connection, fragmentation-safe; raw bytes (base64/hex), SNI, ALPN,
  cipher suites, extensions, supported versions/groups, GREASE detection, plus **JA3**, **JA4**,
  **JA4_r**, **JA4_o** and **JA4H**.
- **Client identification** — combined TLS/JA3/JA4/user-agent/header-set verdicts (curl, wget,
  python-requests, aiohttp, httpx, Node, Java, Go, OpenSSL, Chromium, …) with UA-spoof detection,
  confidence, candidates and evidence notes.
- **Data-source engine** — priority-ordered `embedded` / `file` / `remote` / `command` providers for
  the `ja4`, `datacenter_cidr`, `residential_proxy_cidr` and `datacenter_orgs` datasets; ETag
  revalidation, on-disk cache, mtime hot reload, masked credentials and a generic admin API/UI.
- **IP intelligence** — offline CIDR/org classification, plus an ordered `builtin` / `http` /
  `command` lookup chain (ipwho.is → ip-api.com → ipinfo.io), field mapping, per-provider stats and
  a chain-test endpoint.
- **Admin console** (`/ui/`) — React + Ant Design, 18 pages: overview, echo settings, IP intel,
  data sources, lookup chain, JA4 library, monitoring, query logs, audit trail, notifications,
  users, access control, security, integrations/webhooks, system settings, API docs and a toolbox.
- **Account system** — first-run setup wizard, JWT sessions, `admin`/`viewer` roles, PBKDF2-SHA256
  passwords, registration toggle, disabled-account token revocation, last-admin protection.
- **Security controls** — named API keys (`X-API-Key`, SHA-256 at rest, scoped/expiring), shared
  token, IP allow/deny rules, echo rate limiting, request body cap, CORS, security headers,
  maintenance mode, log retention, JWT rotation, SQLite backup, audit trail and signed webhooks.
- **Operations** — Prometheus `/metrics`, metrics summary API, OpenAPI 3.0.3 document, CSV/JSON
  exports, saved log views, in-app notifications, request replay.
- **Build & release** — `Makefile`, `//go:embed` single binary, GoReleaser (6 platform targets,
  archives, checksums), GitHub Actions CI and tag-triggered releases, Dockerfile.

[Unreleased]: https://github.com/crawler-requests/echo-server/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/crawler-requests/echo-server/releases/tag/v1.0.0
