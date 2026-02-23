# VAOL Multi-Region Reference (v1.0)

This reference describes a conservative multi-region deployment pattern that preserves ledger integrity.

## 1. Model

Use active/passive regions for writes:

1. Region A: active writer
2. Region B: warm standby writer
3. Read-only verification/export can run in both regions

## 2. Data Replication

1. PostgreSQL physical/logical replication with WAL archiving.
2. Object storage cross-region replication with versioning and retention lock.
3. Rekor/anchor continuity validated in both regions.

## 3. Write Safety

1. Exactly one active append endpoint globally.
2. Failover promotion is explicit and audited.
3. Promoted region must pass startup integrity checks before write enablement.

## 4. Regional Failover Sequence

1. Freeze global append traffic.
2. Promote standby database and writer region.
3. Run startup validation + strict bundle verification in promoted region.
4. Re-enable append traffic via global routing.

## 5. Anti-Split-Brain Controls

1. Global routing policy with single write target.
2. Automated health checks do not auto-enable second writer without explicit fencing.
3. Alert on concurrent append traffic observed in both regions.

## 6. Validation Cadence

1. Weekly synthetic failover drill.
2. Monthly full DR drill with auditor transcript output.
3. Quarterly chaos test including checkpoint continuity verification.

