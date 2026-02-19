# VAOL Examples

Runnable examples demonstrating VAOL integration patterns.

## Prerequisites

Start the VAOL server locally:

```bash
# Option A: Docker Compose (includes PostgreSQL + OPA)
make docker-up

# Option B: Binary with in-memory store (quickest)
make build
./bin/vaol-server --addr :8080 --auth-mode disabled --policy-mode allow-all
```

## Examples

| Directory | Description |
|-----------|-------------|
| `go/` | Direct HTTP client in Go — append, verify, export |
| `python/` | Python SDK — auto-instrumented OpenAI calls |
| `typescript/` | TypeScript SDK — auto-instrumented OpenAI calls |

## Running

```bash
# Go
cd examples/go && go run main.go

# Python (requires: pip install vaol httpx)
cd examples/python && python main.py

# TypeScript (requires: npm install @vaol/sdk openai)
cd examples/typescript && npx tsx main.ts
```
