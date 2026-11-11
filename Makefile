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

.PHONY: help frontend build build-fast test vet lint snapshot release-snapshot docker clean run

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

clean: ## Remove build artifacts
	rm -rf $(BINARY) dist frontend/dist

run: build ## Build and run the server in the foreground
	./$(BINARY)
