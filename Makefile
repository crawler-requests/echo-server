# Echo Server — single-binary build helpers.
#
# The React console in frontend/ is compiled to static assets and embedded into
# the Go executable via //go:embed. Always build the frontend before `go build`,
# otherwise the binary ships a stale or missing UI.

BINARY      := echo-server
VERSION     ?= dev
COMMIT      := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
	-X main.serverVersion=$(VERSION) \
	-X main.buildCommit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)

.PHONY: help frontend build build-fast test vet lint snapshot release-snapshot docker docker-smoke clean run loadtest lite ghcr-prune

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

frontend: ## Install deps and build the console into frontend/dist
	cd frontend && npm ci --no-audit --no-fund && npm run build

build: frontend ## Build the self-contained binary (UI embedded)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

build-fast: ## Build the binary without rebuilding the frontend (uses existing dist)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

test: ## Run the full test suite with the race detector
	go test ./... -race -count=1

vet: ## Run go vet
	go vet ./...

lint: ## Fail if any Go file is not gofmt-formatted
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then echo "gofmt needed for:"; echo "$$out"; exit 1; fi

snapshot: ## Cross-compile all release targets locally (no publish)
	goreleaser build --snapshot --clean

release-snapshot: ## Produce archives + checksums locally (no publish)
	goreleaser release --snapshot --clean

GOPROXY ?= https://proxy.golang.org,direct

docker: ## Build the container image (version injected from git)
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg GOPROXY=$(GOPROXY) \
		-t $(BINARY):$(VERSION) .

# The same end-to-end contract CI's Docker job enforces: unprivileged UID,
# baked health probe, a working console, version injection, and a probe that
# stays correct with the plain listener moved or disabled.
docker-smoke: docker ## Run the image end to end (console, version, health probe)
	@set -e; \
	img=$(BINARY):$(VERSION); \
	cleanup() { docker rm -f es-smoke es-smoke-tls es-smoke-moved >/dev/null 2>&1 || true; }; \
	trap cleanup EXIT; \
	docker run -d --name es-smoke -p 127.0.0.1::23231 \
		-e ECHO_SERVER_ADMIN_USERNAME=smoke -e ECHO_SERVER_ADMIN_PASSWORD='smoke-pass-123' $$img >/dev/null; \
	p=$$(docker port es-smoke 23231/tcp | awk -F: '{print $$NF}'); \
	for i in $$(seq 1 30); do curl -fsS http://127.0.0.1:$$p/health >/dev/null 2>&1 && break; sleep 1; done; \
	echo "health:  $$(curl -fsS http://127.0.0.1:$$p/health)"; \
	curl -fsS http://127.0.0.1:$$p/ui/ | grep -q 'id="root"' && echo "console: ok"; \
	curl -fsS http://127.0.0.1:$$p/ip | grep -q '"ip"' && echo "/ip:     ok"; \
	tok=$$(curl -fsS -X POST http://127.0.0.1:$$p/api/login -H 'Content-Type: application/json' \
		-d '{"username":"smoke","password":"smoke-pass-123"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])'); \
	curl -fsS http://127.0.0.1:$$p/api/system -H "Authorization: Bearer $$tok" \
		| python3 -c 'import json,sys;d=json.load(sys.stdin);print("version: "+d["version"]+"  commit: "+d["build_commit"])'; \
	docker exec es-smoke echo-server healthcheck && echo "probe(default): ok"; \
	docker run -d --name es-smoke-tls -p 127.0.0.1::23232 -e HTTP_PORT=0 \
		-e ECHO_SERVER_ADMIN_PASSWORD='smoke-pass-123' $$img >/dev/null; \
	s=$$(docker port es-smoke-tls 23232/tcp | awk -F: '{print $$NF}'); \
	for i in $$(seq 1 30); do curl -fskS https://127.0.0.1:$$s/health >/dev/null 2>&1 && break; sleep 1; done; \
	docker exec es-smoke-tls echo-server healthcheck && echo "probe(HTTP_PORT=0): ok"; \
	docker run -d --name es-smoke-moved -p 127.0.0.1::8080 -e HTTP_PORT=8080 \
		-e ECHO_SERVER_ADMIN_PASSWORD='smoke-pass-123' $$img >/dev/null; \
	m=$$(docker port es-smoke-moved 8080/tcp | awk -F: '{print $$NF}'); \
	for i in $$(seq 1 30); do curl -fsS http://127.0.0.1:$$m/health >/dev/null 2>&1 && break; sleep 1; done; \
	curl -fsS http://127.0.0.1:$$m/health >/dev/null; \
	docker exec es-smoke-moved echo-server healthcheck && echo "probe(HTTP_PORT=8080): ok"

clean: ## Remove build artifacts
	rm -rf $(BINARY) dist frontend/dist

run: build ## Build and run the server in the foreground
	./$(BINARY)

lite: ## Build the lite binary (no database; /ip and /echo only at runtime)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-lite .
	@echo "run it with: ECHO_SERVER_LITE=1 ./$(BINARY)-lite"

ghcr-prune: ## Dry-run the GHCR retention window (GHCR_KEEP=3, GH_TOKEN=...); add APPLY=1 to delete
	go run ./tools/ghcr-prune -owner $(or $(GHCR_OWNER),crawler-requests) -package $(BINARY) \
		-keep $(or $(GHCR_KEEP),3) $(if $(APPLY),-apply)

loadtest: ## High-concurrency load test against a running lite server (CONNS=100000)
	go run ./tools/loadtest -mode $(or $(MODE),drive) -c $(or $(CONNS),100000) \
		-addr $(or $(ADDR),127.0.0.1:23231) -path $(or $(PATH),/ip) -la $(or $(LA),127.0.0.1)
