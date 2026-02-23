# VAOL External Audit Readiness Package

This document defines the package required before commissioning an independent security/cryptography audit.

## 1. Audit Scope

Required audit streams:

1. Cryptography implementation review (DSSE, signer backends, verifier strict profiles)
2. Ledger integrity model review (hash chain, Merkle proofs/checkpoints, startup restore)
3. Multi-tenant authz review (REST + gRPC parity, cross-tenant controls)
4. Policy/governance enforcement review (fail-closed behavior, deterministic denies)

## 2. Evidence Package Checklist

Provide to auditor:

1. Threat model (current release)
2. Architecture and crypto design docs
3. API + protobuf contracts
4. Test evidence:
   1. unit/e2e/tamper reports
   2. strict verification reports
5. Release provenance artifacts:
   1. SBOM
   2. checksums
   3. signed release artifacts
6. Operational controls:
   1. DR playbook
   2. compliance operations baseline
   3. key rotation and retention evidence

## 3. Auditor Reproducibility Path

1. Deploy reference stack (Docker Compose or Helm production profile).
2. Run demo storyline:
   1. compliant request accepted
   2. non-compliant request denied
   3. export bundle
   4. offline strict verification
   5. tamper test deterministic failure
3. Validate checkpoint continuity and anchor evidence.

## 4. Exit Criteria for Audit Completion

1. All critical findings remediated and retested.
2. High findings have accepted remediation plan with deadlines.
3. Public remediation report produced for open-source consumers.
4. v1.0 tag gated on completed remediation evidence.

