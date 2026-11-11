# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `1.x` | ✅ |
| `< 1.0` (pre-release builds, snapshots) | ❌ |

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Please use GitHub's private vulnerability reporting:

<https://github.com/crawler-requests/echo-server/security/advisories/new>

Include as much of the following as you can:

- affected version (`GET /api/system` → `version`, or the release tag),
- deployment shape (plain HTTP console, HTTPS echo, reverse proxy, internet-facing?),
- a minimal reproduction (request/command, configuration keys involved),
- impact assessment (authentication bypass, secret disclosure, SSRF, DoS, …).

You will get an acknowledgement within **3 business days**, and a remediation plan or a
request for more information within **10 business days**. We aim to ship a fixed release within
**30 days** for confirmed high-severity issues, and will credit reporters in the release notes
unless you ask to stay anonymous.

## Scope notes

This is a self-hosted debugging service and some behaviour is intentional by design:

- The echo endpoint reflects request headers and bodies back to the caller. Do not send secrets
  to it; treat its responses as sensitive if the request was sensitive.
- Webhooks can post to arbitrary URLs, and `command` providers execute operator-supplied
  commands. Both are **admin-only** features: a compromised admin account already owns the host.
- Remote dataset / IP-intelligence providers can fetch arbitrary URLs configured by an admin
  (an intentional SSRF surface for integrations).
- `GET /api/openapi.json`, `/health`, `/metrics`, and the echo endpoint are intentionally public
  unless `require_token` is enabled. `/metrics` can be restricted with the shipped IP allow/deny
  rules or a reverse proxy.
- Rate limiting currently applies to echo traffic only; put the login/setup endpoints behind a
  reverse proxy with rate limiting if the console is exposed to the internet.

Reports about these documented behaviours are still welcome as hardening suggestions, but they
are not treated as vulnerabilities on their own.
