.PHONY: all build test lint clean run e2e tamper-test bench sdk-python sdk-typescript demo-auditor policy-test help

BINARY_DIR := bin
GO := go
GOFLAGS := -race

all: build

## Build

build: build-server build-cli build-proxy

build-server:
	$(GO) build -o $(BINARY_DIR)/vaol-server ./cmd/vaol-server

build-cli:
	$(GO) build -o $(BINARY_DIR)/vaol ./cmd/vaol-cli

build-proxy:
	$(GO) build -o $(BINARY_DIR)/vaol-proxy ./cmd/vaol-proxy

## Test

test:
	$(GO) test $(GOFLAGS) -cover ./pkg/...

test-cover:
	$(GO) test $(GOFLAGS) -coverprofile=coverage.out ./pkg/...
	$(GO) tool cover -html=coverage.out -o coverage.html

e2e:
	docker compose -f deploy/docker/docker-compose.yml up -d --wait
	$(GO) test $(GOFLAGS) -tags=e2e -timeout=120s ./tests/e2e/...
	docker compose -f deploy/docker/docker-compose.yml down

tamper-test:
	$(GO) test $(GOFLAGS) -tags=tamper -timeout=60s -v ./tests/tamper/...

demo-auditor:
	./scripts/demo_auditor.sh

bench:
	$(GO) test -bench=. -benchmem ./pkg/merkle/... ./pkg/signer/... ./pkg/record/...

policy-test:
	opa test policies/ -v

## SDK

sdk-python:
	cd sdk/python && pip install -e ".[dev]" && pytest tests/

sdk-typescript:
	cd sdk/typescript && npm install && npm test

## Lint

lint: lint-go lint-python lint-typescript

lint-go:
	golangci-lint run ./...

lint-python:
	cd sdk/python && ruff check vaol/ tests/

lint-typescript:
	cd sdk/typescript && npx eslint src/

## Security

security:
	gosec ./...
	trivy fs --scanners vuln .

## Docker

docker-build:
	docker build -f deploy/docker/Dockerfile.server -t vaol-server:latest .
	docker build -f deploy/docker/Dockerfile.proxy -t vaol-proxy:latest .

docker-up:
	docker compose -f deploy/docker/docker-compose.yml up -d

docker-down:
	docker compose -f deploy/docker/docker-compose.yml down

## Clean

clean:
	rm -rf $(BINARY_DIR) coverage.out coverage.html
	$(GO) clean -cache

## Help

help:
	@echo "VAOL — Verifiable AI Output Ledger"
	@echo ""
	@echo "Build targets:"
	@echo "  make build          Build all binaries"
	@echo "  make build-server   Build vaol-server"
	@echo "  make build-cli      Build vaol CLI"
	@echo "  make build-proxy    Build vaol-proxy"
	@echo ""
	@echo "Test targets:"
	@echo "  make test           Run unit tests"
	@echo "  make test-cover     Run tests with coverage report"
	@echo "  make e2e            Run end-to-end tests (requires Docker)"
	@echo "  make tamper-test    Run tamper detection test suite"
	@echo "  make bench          Run benchmarks"
	@echo "  make policy-test    Run OPA/Rego policy tests"
	@echo "  make demo-auditor   Run reproducible auditor demo storyline"
	@echo ""
	@echo "SDK targets:"
	@echo "  make sdk-python     Install and test Python SDK"
	@echo "  make sdk-typescript Install and test TypeScript SDK"
	@echo ""
	@echo "Other targets:"
	@echo "  make lint           Run all linters"
	@echo "  make security       Run security scanners"
	@echo "  make docker-build   Build Docker images"
	@echo "  make docker-up      Start local stack"
	@echo "  make docker-down    Stop local stack"
	@echo "  make clean          Clean build artifacts"
