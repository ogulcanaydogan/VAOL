# Architecture Decision Records

Use ADRs to document irreversible or high-impact technical decisions.

## When ADRs are required

- cryptographic design changes (signing, canonicalization, hash chain, Merkle proofs)
- schema or API contract changes that affect verifier compatibility
- policy/governance model changes (fail-closed behavior, tenant isolation rules)
- storage architecture changes that alter audit guarantees

## Naming

`NNNN-short-title.md` (for example: `0001-merkle-checkpoint-anchoring.md`)

## Required sections

- Context
- Decision
- Consequences
- Alternatives considered
- Security/compliance impact

Use `docs/adr/0000-template.md` as the starting point.
