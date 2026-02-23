# VAOL Disaster Recovery Playbook

This playbook defines recovery steps for ledger integrity and service continuity.

## 1. Recovery Objectives

Default targets (adjust per tenant/regulatory profile):

1. RPO: <= 5 minutes
2. RTO: <= 30 minutes

## 2. Preconditions

1. PostgreSQL PITR enabled.
2. Object storage versioning/retention lock enabled (if encrypted blobs are used).
3. Signed checkpoints persisted and anchored.
4. Startup fail-closed checks enabled.

## 3. Incident Classes

1. Data-plane outage: PostgreSQL unavailable/corrupt.
2. Control-plane outage: API nodes unavailable.
3. Integrity divergence: startup checks fail (checkpoint/root/anchor mismatch).

## 4. Recovery Runbook

### Step 1: Freeze writes

1. Remove append traffic from load balancer.
2. Keep read-only endpoints available only if integrity is known-good.

### Step 2: Restore data plane

1. Restore PostgreSQL to last known-good PITR timestamp.
2. Restore object store blobs only if encrypted payload endpoints are in scope.

### Step 3: Bring up candidate writer

1. Start `vaol-server` with:
   1. `--fail-on-startup-check=true`
   2. `--anchor-continuity-required=true`
   3. production auth/policy flags
2. Confirm startup integrity checks pass.

### Step 4: Verify ledger continuity

1. Run strict verify on recent export bundle:

```bash
vaol export --tenant <tenant> --after <iso-time> --output /tmp/dr-bundle.json
vaol verify bundle /tmp/dr-bundle.json --profile strict --transcript-json /tmp/dr-verify.json
```

2. Validate checkpoint monotonicity and anchor continuity.

### Step 5: Resume writes

1. Run one append smoke test.
2. Confirm record is retrievable and proof validates.
3. Re-enable append traffic.

## 5. Post-Incident Evidence

Archive these artifacts for audit:

1. PITR restore metadata (target timestamp, WAL position).
2. Startup logs proving checkpoint/root/anchor validation.
3. Pre/post recovery bundle verification transcript.
4. Timeline of traffic freeze/resume decisions.

## 6. Fail-Closed Criteria

Do not resume writes if any of these fail:

1. Startup root/checkpoint mismatch
2. Signature verification failure on latest checkpoint
3. Anchor continuity mismatch when required
4. Strict bundle verification failure on untampered bundle

