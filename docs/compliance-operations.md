# VAOL Compliance Operations Baseline

This document defines operational controls required for audit-ready operation.

## 1. Service-Level Objectives

1. Append availability (`/v1/records` + `AppendRecord`): 99.9% monthly
2. Verification availability (`/v1/verify*` + `VerifyRecord`): 99.9% monthly
3. Checkpoint freshness: max 5 minutes since last checkpoint in production
4. Integrity startup checks: 100% pass rate on production restarts

## 2. Mandatory Runtime Settings (Production)

1. `--auth-mode=required`
2. `--policy-mode=fail-closed`
3. `--fail-on-startup-check=true`
4. `--anchor-continuity-required=true`
5. `--verify-strict-online-rekor=true` for connected environments

## 3. Daily Controls

1. Check CI/main branch status for release workflows.
2. Verify latest checkpoint exists and tree size increased as expected.
3. Review policy deny reason-code distribution for anomalies.
4. Confirm no cross-tenant access denials are being auto-retried abnormally.

## 4. Weekly Controls

1. Run strict verification on a sampled auditor bundle per tenant tier.
2. Review key revocation file freshness and signer inventory.
3. Confirm encrypted payload retention jobs emitted tombstones.
4. Confirm key-rotation metadata events executed (if rotation window hit).

## 5. Monthly Controls

1. Run DR tabletop + restore drill (see `docs/dr-playbook.md`).
2. Rotate signing/encryption keys per policy.
3. Export and archive:
   1. verification transcripts
   2. checkpoint continuity report
   3. retention and key-rotation evidence
4. Revalidate threat model assumptions and update if architecture changed.

## 6. Alerting Baseline

Trigger pages for:

1. startup integrity failure
2. checkpoint publish failure
3. strict verification failure spike
4. policy engine unavailable rate above threshold
5. append latency SLO breach

## 7. Auditor Evidence Bundle (Operational)

For each reporting period, archive:

1. release/version inventory
2. security scan + SBOM artifacts
3. signed checkpoint timeline
4. strict verification transcripts
5. retention/key-rotation logs and tombstones

