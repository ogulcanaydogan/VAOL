# VAOL Public Remediation Report Template

Use this template to publish sanitized remediation status after external audit completion.

## 1. Release Context

1. Release target: `<v1.0.0>`
2. Audit partner: `<firm>`
3. Report publication date: `<YYYY-MM-DD>`
4. Scope baseline commit/tag: `<git-ref>`

## 2. Findings Summary

| Severity | Count | Resolved | Accepted Plan |
|---|---:|---:|---:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Medium | 0 | 0 | 0 |
| Low | 0 | 0 | 0 |

## 3. Resolved Findings

For each resolved finding:

1. Finding ID: `<id>`
2. Severity: `<Critical|High|Medium|Low>`
3. Summary: `<short description>`
4. Fix commit(s): `<hashes>`
5. Linked issue(s): `<#issue>`
6. Retest evidence: `<artifact link/path>`

## 4. Planned Remediation (Open Findings)

For accepted but not-yet-resolved findings:

1. Finding ID: `<id>`
2. Severity: `<High|Medium|Low>`
3. Mitigation currently in place: `<description>`
4. Planned fix release: `<version>`
5. Target date: `<YYYY-MM-DD>`
6. Owner: `<name/team>`
7. Linked issue(s): `<#issue>`
8. Risk acceptance approver (if applicable): `<name>`

## 5. Verification Evidence Bundle

Include links to:

1. CI run showing required matrix passing.
2. Auditor demo transcript and tamper-fail evidence.
3. Bundle verification transcript (`strict` profile).
4. SBOM/provenance artifacts.
5. Startup restore benchmark gate output (`startup-restore-bench.txt`).

## 6. Integrity Statement

`VAOL maintainers attest that all published remediation entries map to verifiable repository commits and test evidence artifacts.`
