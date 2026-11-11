# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
