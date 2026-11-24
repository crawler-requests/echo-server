# Release checklist

The release pipeline is: **tag → GitHub Actions → GoReleaser → GitHub Release**. Everything below
is designed so a release is a repeatable 15-minute operation.

## Before the first public release

- [x] `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, issue/PR templates, `CHANGELOG.md`
- [x] Repository description (English) and topics
- [x] CI green on `main` (`Build and test`, `Docker image`)
- [x] `goreleaser check` and a local `goreleaser release --snapshot --clean`
- [x] Single-binary smoke test from an empty directory (`/ui/` 200, `/api/system` version injected)
- [ ] Rotate/remove any local test data before tagging (see below)
- [ ] Confirm the `v1.0.0` version in `CHANGELOG.md` matches the tag

## Per-release checklist

1. **Freeze and test**
   - `make test` (race detector) and `make vet` locally.
   - CI on `main` must be green.
2. **Update the changelog**
   - Move `[Unreleased]` entries into a new `[x.y.z] - YYYY-MM-DD` section and update the links.
3. **Tag and push** (two independent releases)
   ```bash
   # full product (console, database, admin API)
   git tag -a v1.0.0 -m "v1.0.0"
   git push origin v1.0.0

   # lite build (no database; /ip and /echo only) — separate tag namespace
   git tag -a 1.0.0 -m "1.0.0"
   git push origin 1.0.0
   ```
4. **Watch the release workflow**
   ```bash
   gh run watch
   gh release view v1.0.0
   ```
5. **Verify the published artifacts**
   - Download one archive, extract it into an empty directory, run `./echo-server`, check
     `http://HOST:23231/ui/` and `GET /api/system` (`version` = tag, `build_commit` = tagged commit).
   - `sha256sum -c checksums.txt` inside the release download directory.
   - **Lite release**: download `echo-server-lite_*`, run it with `ECHO_SERVER_LITE=1`, confirm
     `/ip` answers, `/ui/` and `/api/config` are 404, and no `echo.db` appears next to the binary.
   - **Container image** — the `image` job pushes to GHCR with the tag as `v1.2.3`, `1.2`, `1` and
     `latest`:
     ```bash
     docker pull ghcr.io/crawler-requests/echo-server:v1.0.0
     docker run -d -p 23231:23231 -e ECHO_SERVER_ADMIN_PASSWORD=x \
       ghcr.io/crawler-requests/echo-server:v1.0.0
     curl -sf http://127.0.0.1:23231/health
     docker image inspect ghcr.io/crawler-requests/echo-server:v1.0.0 --format '{{.Architecture}}'
     ```
     The package must be **public** for anonymous pulls: GHCR inherits the repository's visibility on
     first publish, but if the pull above fails with `unauthorized`, open
     *Org → Packages → echo-server → Settings* and set visibility to *Public* once.
6. **Post-release**
   - Announce in the project README/discussions if applicable.
   - Bump `serverVersion`'s development default only if the project starts cutting maintenance
     branches (release builds always get the tag value from ldflags).

## Local dry run (no publish)

```bash
make release-snapshot     # dist/ archives + checksums for all six targets
make snapshot             # cross-compiled binaries only
```

## Rollback

A published GitHub Release can be edited or deleted, and the tag re-pointed:

```bash
gh release delete v1.0.0 --yes
git push origin :refs/tags/v1.0.0   # delete the remote tag
```

Prefer shipping a `v1.0.1` patch release over silently replacing artifacts.

## Secrets and data hygiene

- `server-url.txt`, `echo-server.log`, the compiled `echo-server`, SQLite databases and
  `frontend/dist/` are gitignored — never commit them.
- `ECHO_SERVER_JWT_SECRET`, `ECHO_SERVER_ADMIN_PASSWORD`, API keys, webhook secrets and provider
  credentials must never appear in a commit, issue, or screenshot. The API masks them as `***`.
- The admin UI's database backup (`/api/system/backup`) contains password hashes and secrets; treat
  it as sensitive and never attach it to an issue.
