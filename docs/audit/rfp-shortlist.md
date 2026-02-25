# VAOL External Audit RFP Shortlist

This document is the working shortlist and scoring rubric for selecting an independent security/cryptography auditor for VAOL `v1.0.0`.

## 1. Mandatory Scope Coverage

Each candidate must explicitly cover all areas below in the statement of work:

1. DSSE signing and verifier profiles (`basic`, `strict`, `fips`) correctness.
2. Hash-chain and Merkle integrity, including checkpoint handling and startup restore.
3. Tenant isolation and authorization parity across REST and gRPC.
4. Policy fail-closed behavior and deterministic deny semantics.
5. Supply-chain controls (release provenance, SBOM, dependency scanning).

## 2. Candidate Scoring Rubric

Score each candidate 1-5 per category; weighted total determines ranking.

| Category | Weight | Notes |
|---|---:|---|
| Cryptography review depth | 30% | Prior reviews of DSSE, transparency logs, KMS/HSM integrations |
| Ledger/integrity systems expertise | 20% | Experience with append-only logs, Merkle proof systems |
| Regulated environment experience | 20% | HIPAA/SOC2/ISO27001 exposure and evidence practices |
| Open-source disclosure quality | 15% | Can provide public-safe remediation summaries |
| Delivery reliability and timeline | 15% | Ability to complete within target release window |

## 3. Candidate Shortlist Template

Populate this table before SOW finalization:

| Firm | Status | Score | Strengths | Risks | Proposed Start | Proposed End |
|---|---|---:|---|---|---|---|
| `<firm-1>` | evaluating | `0.0` |  |  |  |  |
| `<firm-2>` | evaluating | `0.0` |  |  |  |  |
| `<firm-3>` | evaluating | `0.0` |  |  |  |  |

## 4. Scoring Worksheet (Deterministic)

Use this formula for each firm:

1. Weighted score:
   1. `total = (crypto*0.30) + (ledger*0.20) + (regulated*0.20) + (oss*0.15) + (delivery*0.15)`.
2. Minimum acceptance gates:
   1. `crypto >= 4.0`
   2. `ledger >= 4.0`
   3. proposed timeline <= 8 weeks from kickoff.
3. Tie-break order:
   1. higher `crypto`
   2. higher `ledger`
   3. lower delivery risk.

## 5. Due-Diligence Questions

1. What cryptographic review methodology is used for signature envelope systems?
2. Do you provide exploitability-ranked findings and reproducible PoCs?
3. How are false positives handled and appealed?
4. What retest turnaround is guaranteed for critical/high findings?
5. Can you provide references for prior open-source security audits?

## 6. Selection Timeline and Owners

Record actual dates for traceability:

1. RFP sent date: `<YYYY-MM-DD>`
2. Q&A close date: `<YYYY-MM-DD>`
3. Final proposal due date: `<YYYY-MM-DD>`
4. Selection meeting date: `<YYYY-MM-DD>`
5. SOW sign date: `<YYYY-MM-DD>`
6. VAOL owner: `<name>`

## 7. Selection Decision Record

Record final selection here:

1. Selected firm: `<name>`
2. Selection date: `<YYYY-MM-DD>`
3. Decision owner: `<name>`
4. Tie-break rationale: `<summary>`
5. Approved budget: `<amount and currency>`
