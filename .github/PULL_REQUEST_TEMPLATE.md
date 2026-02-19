## Summary

- What changed:
- Why:
- Risk level: low / medium / high

## Validation

- [ ] `go test ./...`
- [ ] Relevant SDK tests
- [ ] Docs updated for behavior/API changes

## Security and Compliance Checklist

- [ ] No secrets or plaintext sensitive data introduced
- [ ] Tenant isolation behavior validated (read/write paths)
- [ ] Fail-closed behavior preserved where required
- [ ] Retention/privacy mode impact considered

## Cryptography Change Checklist (Required if applicable)

- [ ] No weakening of signature, hashing, canonicalization, or Merkle guarantees
- [ ] DSSE payload type and signed bytes remain deterministic
- [ ] Backward compatibility impact documented
- [ ] Added/updated verifier and tamper tests
- [ ] Updated `docs/threat-model.md` for new attack surface

## Schema / Signing Contract Changes (Required if applicable)

- [ ] Updated `schemas/` and compatibility notes
- [ ] Updated `proto/` (if relevant) and parity checks
- [ ] Added migration notes and release-note entry
- [ ] Confirmed offline verifier can still reproduce results deterministically
