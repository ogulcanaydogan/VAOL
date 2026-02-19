# Contributing to VAOL

Thank you for your interest in contributing to the Verifiable AI Output Ledger.

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run tests: `make test`
6. Run linters: `make lint`
7. Commit with a descriptive message
8. Push and open a Pull Request

## Development Setup

### Prerequisites

- Go 1.23+
- Python 3.11+
- Docker and Docker Compose
- PostgreSQL 16+ (or use Docker Compose)

### Build

```bash
make build        # Build all binaries
make test         # Run unit tests
make lint         # Run linters
make docker-up    # Start local development stack
```

## Code Style

- **Go**: Follow standard Go conventions. Run `golangci-lint`.
- **Python**: Follow PEP 8. Run `ruff check`. Type annotations required.
- **Rego**: One policy per file. Include comments explaining intent.

## Security

If you discover a security vulnerability, please report it privately.
Do NOT open a public issue for security vulnerabilities.
See `SECURITY.md` for disclosure workflow and response targets.

## Pull Request Guidelines

- One logical change per PR
- Include tests for new functionality
- Update documentation if behavior changes
- Ensure CI passes before requesting review
- Follow `.github/PULL_REQUEST_TEMPLATE.md` checklists
- Crypto/schema/signing changes must update `docs/threat-model.md` and verifier/tamper tests
- Use ADRs in `docs/adr/` for irreversible or high-impact design decisions

## Areas for Contribution

- Additional signing backends (KMS providers, HSM support)
- Storage backends (MySQL, CockroachDB, etc.)
- SDK wrappers for additional LLM libraries
- Policy examples for specific compliance frameworks
- Documentation improvements
- Performance optimizations
- Tamper detection test cases

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
