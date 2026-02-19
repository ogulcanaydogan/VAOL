# Auditor Demo Storyline (Reproducible)

This walkthrough produces an auditor-ready evidence package with one accepted and one denied AI decision, then proves tamper detection offline.

## Scenario

1. Start dependencies (PostgreSQL + OPA).
2. Start `vaol-server` with:
   - fail-closed policy mode
   - local Ed25519 signing key
   - policy path `v1/data/vaol/mandatory_citations`
3. Submit a compliant RAG request (has citation hashes) and receive `201`.
4. Submit a non-compliant RAG request (missing citation hashes) and receive `403`.
5. Export an audit bundle for the tenant.
6. Verify bundle offline with `vaol verify bundle` and the public key (pass).
7. Tamper the bundle signature and re-run verification (fail).
8. Produce a Markdown evidence report with artifact paths.

## One-Command Run

```bash
./scripts/demo_auditor.sh
```

The script creates timestamped output under:

```text
tmp/demo-auditor/<UTC timestamp>/
```

Key outputs:

- `artifacts/audit-bundle.json`
- `artifacts/audit-bundle-tampered.json`
- `artifacts/verify-pass.log`
- `artifacts/verify-fail.log`
- `artifacts/auditor-report.md`
- `logs/vaol-server.log`

## Environment Overrides

- `VAOL_DEMO_TENANT` (default: `acme-health`)
- `VAOL_DEMO_ADDR` (default: `127.0.0.1:18080`)
- `VAOL_DEMO_DSN` (default: `postgres://vaol:vaol@localhost:5432/vaol?sslmode=disable`)
- `VAOL_DEMO_OPA_POLICY` (default: `v1/data/vaol/mandatory_citations`)
- `VAOL_DEMO_KEEP_STACK=1` to leave Docker services running after completion

## Auditor Verification Checklist

1. Denied response contains `decision.rule_ids` including `rag_missing_citations`.
2. Exported bundle includes signed DSSE envelope(s) and Merkle proof(s).
3. `vaol verify bundle` passes on the untampered bundle.
4. `vaol verify bundle` fails on the tampered bundle with signature verification errors.
5. Report captures request IDs and artifact file locations for retention.
