# Echo Server Product Design

## Overview
Echo Server is a self-contained HTTPS service that echoes full request metadata (headers, body, TLS ClientHello, JA3 fingerprint) plus IP geolocation and connection classification (datacenter/residential). The single Go binary embeds a React + Ant Design admin frontend, uses SQLite for persistent configuration and query history, supports JWT login and optional API token authentication, and allows administrators to toggle which fields are returned in echo responses.

## Goals
- Single distributable binary (no external dependencies at runtime)
- Complete request/TLS/IP fingerprinting for crawler-requests organization
- Admin UI for configuration and history inspection without restarting the service
- Flexible deployment: public or token-protected
- All data stored under `~/.echo-server/` (hidden directory)

## Non-Goals
- Multi-user RBAC
- Automatic daily updates of embedded datacenter ranges
- HTTP/2 or QUIC fingerprinting beyond current JA3 support
- Docker / systemd packaging

## Architecture

### Backend (Go)
- `main.go`: HTTPS server with self-signed cert, TLS ClientHello capture via custom listener, echoHandler orchestration
- `echo.go`: pure `buildEchoResponse` and `extractClientIP` (for testing)
- `tls_capture.go`: helloListener / helloConn + `populateClientHello` + `computeJA3`
- `ip_classify.go`: embedded `data/datacenter_ranges.csv` + `classifyIP(ip) -> datacenter|residential|proxy|unknown`
- `storage.go`: SQLite abstraction (`~/.echo-server/echo.db`) with tables:
  - `config(key TEXT PRIMARY KEY, value TEXT)` — return-field toggles + `require_token`
  - `query_log(...)` — minimal history (ts, method, path, ip, connection_type, country)
- `auth.go`: JWT (HS256, 1h expiry) + API token middleware; `loginHandler` (hard-coded admin/admin for demo)

Config keys currently supported:
- `show_ja3` (default true)
- `show_ip` (default true)
- `show_raw` (default true)
- `require_token` (default false) — when true, `/` requires valid JWT or `X-API-Token`

### Frontend (TypeScript + React + Ant Design)
- Embedded via `//go:embed frontend/dist`
- Served at `/ui/`
- Routes:
  - `/api/login` — POST {username, password} → {token}
  - `/api/config` — GET/POST (JWT protected) read/write config toggles
  - `/api/logs` — GET (JWT protected) recent query history
- `src/Login.tsx`, `src/Admin.tsx`, `src/App.tsx` — real Ant Design components (Card, Form, Switch, Table, Button)
- Admin page allows toggling return fields; changes are persisted to SQLite and immediately affect subsequent echo responses
- History table shows last 20 queries with connection classification and country

### Data Flow
1. Client sends request (optionally with `X-Forwarded-For`)
2. `echoHandler` calls `fetchIPInfo` → `classifyIP` + ipinfo.io (or fallback)
3. `LogQuery` writes minimal record to SQLite
4. Config toggles (`GetConfig`) decide whether to include JA3 / IP / raw ClientHello in JSON
5. Admin UI reads/writes the same config keys via protected endpoints; live echo responses reflect the new values on next request

## Security
- JWT secret is hard-coded for demo (production should load from env / SQLite)
- API token stored in `config` table under key `api_token`
- All admin endpoints require `Authorization: Bearer <jwt>`
- When `require_token=true`, the echo endpoint itself also enforces token/JWT

## Storage Location
`~/.echo-server/echo.db` (0700 directory). Created on first `initDB()` call.

## Testing Strategy
- Unit tests drive only shipped functions (`classifyIP`, `fetchIPInfo`, `echoHandler`)
- `TestRealHandler_SQLiteConfig` sets config via `SetConfig`, calls real `echoHandler`, asserts resulting JSON omits JA3 when `show_ja3=false`
- Live verification: build binary, start on 18443, two curls with distinct `X-Forwarded-For`, capture JSON, assert all required fields + literal keys present

## Future Extensions (out of scope for current goal)
- Dynamic datacenter list updates via GitHub release
- JA4 / HTTP/2 fingerprinting via utls or godicttls
- Prometheus metrics endpoint
- Multiple admin users with hashed passwords

This design satisfies the complete feature set requested: IP classification + geolocation, embedded React frontend, JWT + API token auth, SQLite-backed admin configuration that directly controls echo response content, and query history.
