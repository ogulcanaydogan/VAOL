# Governance

## Project Model

VAOL is maintained under a maintainer-led model with security-first review gates for cryptography, policy, and schema changes.

## Roles

- Maintainers:
  - approve/reject roadmap and releases
  - own security response and disclosure coordination
  - enforce compatibility and auditability guarantees
- Reviewers:
  - review code and tests in assigned ownership areas
  - validate threat-model implications for security-sensitive changes
- Contributors:
  - submit PRs, tests, docs, and policy bundles per contribution guidelines

## Decision Process

- Minor changes: maintainer approval via PR review.
- Security-sensitive changes (crypto/verifier/schema/policy contracts): two approvals minimum, at least one CODEOWNER.
- Breaking changes: require ADR in `docs/adr/`, migration notes, and maintainer sign-off.

## Release and Compatibility Policy

- Versioning: semantic versioning.
- `v1` schema and API fields are append-only; removals/renames require major version.
- Verifier behavior changes must include compatibility notes and regression tests.

## Security-Critical Paths

The following paths are treated as critical:

- `pkg/signer/`
- `pkg/verifier/`
- `pkg/merkle/`
- `pkg/record/`
- `pkg/policy/`
- `schemas/`
- `proto/`
- `tests/tamper/`

## Conduct and Collaboration

All contributors must follow repository standards in `CONTRIBUTING.md` and respect private disclosure requirements in `SECURITY.md`.
