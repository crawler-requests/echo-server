# Contributing

Thanks for taking the time to contribute. This project is a single Go binary with an embedded
React console; the fastest way to work on it is to build both halves locally.

## Requirements

- Go 1.26+
- Node.js 22+ and npm
- (optional) `goreleaser` v2 for release snapshots

## Build and test

```bash
make build     # build frontend/dist, then embed it into ./echo-server
make test      # go test ./... -race -count=1
make vet       # go vet ./...
```

`frontend/dist` is generated and gitignored. `make build` always rebuilds it; if you run
`go build` directly, build the frontend first or you will embed a stale UI.

Run the server on throwaway ports while developing:

```bash
ECHO_SERVER_DB=/tmp/echo-dev.db PORT=18443 HTTP_PORT=18080 ./echo-server
# console: http://127.0.0.1:18080/ui/
```

## Making a change

1. Open an issue first for anything larger than a bug fix or a small feature, so the design can be
   discussed before you invest time.
2. Keep changes focused; separate refactors from behaviour changes.
3. Add or update tests. Backend tests must run offline (`go test ./...`); network-dependent tests
   must skip with `testing.Short()`.
4. Update `README.md` **and** `README.zh-CN.md` when you change user-visible behaviour or flags.
5. Run `gofmt` (the CI checks it), `make vet` and `make test`.

## Commit messages

Conventional-commit style prefixes are appreciated:

- `feat:` a user-visible feature
- `fix:` a bug fix
- `docs:` documentation only
- `test:` tests only
- `ci:` workflows / release plumbing
- `refactor:`, `chore:`, `style:`

GoReleaser filters `docs`/`test`/`ci`/`chore`/`style` out of the release changelog, so use `feat`
and `fix` for changes users should see.

## Pull requests

- Describe the problem, the approach and how you verified it.
- Include screenshots for console changes.
- CI must be green (`Build and test` + `Docker image`).
- By contributing you agree that your contribution is licensed under the MIT License.
