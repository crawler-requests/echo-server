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
3. **Tag and push**
   ```bash
   git tag -a v1.0.0 -m "v1.0.0"
   git push origin v1.0.0
   ```
4. **Watch the release workflow**
   ```bash
   gh run watch
   gh release view v1.0.0
   ```
5. **Verify the published artifacts**
   - Download one archive, extract it into an empty directory, run `./echo-server`, check
     `http://HOST:8080/ui/` and `GET /api/system` (`version` = tag, `build_commit` = tagged commit).
   - `sha256sum -c checksums.txt` inside the release download directory.
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
