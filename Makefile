# minibox Makefile. Run `make help` for targets.

BIN     := bin/minibox
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all build test smoke vet fmt check-env image bench-image attacks bench clean help

all: build

build: ## Build bin/minibox
	go build -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/minibox

test: ## Run unit tests
	go test ./...

smoke: build ## Run end-to-end smoke tests in this VM (needs `make image`)
	tests/smoke.sh

vet: ## Run go vet
	go vet ./...

fmt: ## Format Go code
	gofmt -w cmd internal tests tools

check-env: ## Check kernel/VM features minibox needs
	scripts/check-env.sh

image: ## Download the Alpine minirootfs into images/alpine
	scripts/get-alpine.sh

bench-image: build ## Build images/bench (Alpine + python3 + busybox httpd)
	scripts/build-bench-image.sh

attacks: build ## Run the attack suite under none/baseline/policy -> results/attacks.*
	tests/attacks/run.py
	scripts/update-docs-results.py

bench: build ## Run the benchmarks -> results/bench.*, results/syscalls.*
	bench/run.py
	scripts/update-docs-results.py

clean: ## Remove build output
	rm -rf bin tests/attacks/bin

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
