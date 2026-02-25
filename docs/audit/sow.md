# VAOL External Security/Cryptography Audit SOW Template

Use this template to execute issue `#20` with a selected independent auditor.

## 1. Engagement Metadata

1. Auditor: `<firm>`
2. Client: VAOL maintainers
3. Engagement window: `<start>` to `<end>`
4. Report due date: `<date>`
5. Retest due date: `<date>`

## 2. Systems In Scope

1. Go server components:
   1. `pkg/api`
   2. `pkg/grpc`
   3. `pkg/record`
   4. `pkg/merkle`
   5. `pkg/signer`
   6. `pkg/verifier`
   7. `pkg/store`
2. CLI verification workflows (`cmd/vaol-cli`).
3. SDK verification-relevant wrappers (Python/TypeScript).
4. Helm and Docker production deployment references.

Out of scope unless explicitly added:

1. Third-party cloud tenancy controls outside VAOL project ownership.
2. Custom downstream app logic not in VAOL repository.

## 3. Required Security Assertions

Auditor must provide explicit pass/fail assertions for:

1. Signature verification cannot be bypassed by payload/envelope mutation.
2. Hash-chain/Merkle integrity detects truncation/tampering deterministically.
3. Tenant isolation prevents cross-tenant read/export/proof leakage.
4. Policy fail-closed behavior is enforced under dependency failure.
5. Strict verification profile behavior is deterministic and documented.

## 4. Required Evidence Inputs

VAOL team will provide:

1. `docs/external-audit-readiness.md`
2. Threat model and architecture docs
3. Latest release notes and changelog
4. Test evidence artifacts (`go`, `python`, `typescript`, `demo_auditor`)
5. SBOM/provenance outputs and dependency scan results

## 5. Deliverables

Auditor shall deliver:

1. Full confidential technical report.
2. Findings list with severity (`Critical`, `High`, `Medium`, `Low`, `Info`).
3. Reproduction steps and affected versions/commits.
4. Retest report for remediated findings.
5. Executive summary suitable for sanitized public disclosure.

Required machine-readable attachments:

1. findings JSON or CSV export with stable finding IDs.
2. mapping of findings to affected files/commits.
3. retest status table keyed by finding ID.

## 6. Severity and SLA

| Severity | Definition | Remediation target |
|---|---|---|
| Critical | Immediate integrity/security compromise | fix before release |
| High | Material risk in production security posture | dated remediation plan or pre-release fix |
| Medium | Important hardening gap | scheduled backlog item with owner/date |
| Low | Minor issue | opportunistic fix |

## 7. Acceptance Criteria

Engagement is complete only when:

1. Critical findings are remediated and retested.
2. High findings have either remediated retest or accepted dated remediation plan.
3. Public-safe remediation summary is published.

## 8. Communication Cadence

1. Weekly status checkpoint during active assessment.
2. Daily updates while critical findings remain open.
3. Final readout meeting with remediation sign-off.

## 9. Milestones and Exit Events

Record and track these mandatory milestones:

1. Kickoff complete: `<YYYY-MM-DD>`
2. Evidence package handoff complete: `<YYYY-MM-DD>`
3. Initial findings report delivered: `<YYYY-MM-DD>`
4. Critical remediation complete: `<YYYY-MM-DD>`
5. High remediation plan accepted: `<YYYY-MM-DD>`
6. Retest complete: `<YYYY-MM-DD>`
7. Public remediation report published: `<YYYY-MM-DD>`

## 10. Required VAOL Evidence Bundle for Auditor

At handoff, include:

1. `VAOL_AUDIT_RUN_MATRIX=1 ./scripts/build_audit_pack.sh` archive output.
2. Latest release notes (`v0.2.28` and onward).
3. Startup restore benchmark artifact (`startup-restore-bench.txt`) showing pass status.
4. Auditor demo artifacts from CI and local transcript bundle.
