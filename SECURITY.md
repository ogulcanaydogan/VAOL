# Security Policy

VAOL is designed for regulated and high-assurance environments. Security issues are handled with priority and coordinated disclosure.

## Reporting a Vulnerability

- Do not open public GitHub issues for security vulnerabilities.
- Report privately to: `security@yapay.ai` (PGP preferred).
- Include:
  - affected component and version
  - reproduction steps and proof-of-concept
  - impact assessment (confidentiality, integrity, availability)
  - any known mitigations

## Response Targets

- Acknowledgement: within 48 hours
- Initial triage: within 5 business days
- Remediation plan: within 10 business days for confirmed issues
- Coordinated disclosure timeline: negotiated per severity and exploitability

## Severity Guidelines

- Critical: signature forgery, verification bypass, cross-tenant data exposure
- High: tamper-evidence bypass, policy bypass, key-handling flaws
- Medium: denial-of-service in control plane, non-default misconfig risks
- Low: documentation gaps, hardening improvements without direct exploit

## Supported Versions

Security fixes are backported to the latest minor release branch and current `main`.

## Cryptography and Evidence Integrity Changes

Changes to signing, hashing, canonicalization, Merkle logic, schema integrity fields, or verifier behavior require:

- threat model update (`docs/threat-model.md`)
- verifier regression tests (`pkg/verifier/*`, `tests/tamper/*`)
- explicit migration notes in release notes
