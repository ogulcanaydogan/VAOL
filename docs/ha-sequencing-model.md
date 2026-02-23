# VAOL HA Sequencing Model (v1.0 Target)

This document defines the sequencing and write-path model used to preserve hash-chain and Merkle integrity in high-availability deployments.

## 1. Scope

Applies to:

1. REST `POST /v1/records`
2. gRPC `AppendRecord`
3. Ingested append-event checkpoint builders that consume ledger writes

Out of scope:

1. Multi-primary concurrent writers
2. Cross-region active/active write arbitration

## 2. Integrity Invariants

All production deployments must preserve these invariants:

1. `sequence_number` is globally monotonic and gap-free within a single writer timeline.
2. `previous_record_hash` of record `N` equals `record_hash` of record `N-1`.
3. `merkle_leaf_index` matches append order and equals Merkle leaf position.
4. Checkpoint `tree_size` never decreases.
5. Tenant isolation does not affect global append order; tenant filtering is read-path only.

## 3. Recommended Topology

Use active/passive API servers with one effective writer at any moment:

1. Active node accepts append traffic.
2. Passive node is warm, read-capable, and can take over on failover.
3. PostgreSQL remains the sequence source of truth.
4. On failover, the promoted node performs startup integrity checks before serving writes.

Do not run active/active writers against one global sequence stream without explicit write fencing.

## 4. Write Fencing Requirements

Before declaring a deployment v1.0-ready, enforce:

1. Single writer service endpoint (load balancer points append routes to one active backend).
2. Orchestration policy that prevents concurrent writer promotion.
3. Startup fail-closed (`--fail-on-startup-check=true`) on all writer candidates.
4. Anchor continuity checks enabled in production (`--anchor-continuity-required=true`).

## 5. Failover Procedure (Writer)

1. Drain traffic from current writer.
2. Promote passive node.
3. Start promoted node with startup checks enabled.
4. Validate:
   1. `GET /v1/health` returns `ok`
   2. latest checkpoint root and tree size are monotonic
   3. append smoke test passes and new record links to prior hash
5. Repoint append traffic.

## 6. Verification Queries

Use these checks in runbooks/automation:

```sql
-- Monotonic sequence growth
SELECT MIN(sequence_number), MAX(sequence_number), COUNT(*) FROM decision_records;

-- Check leaf/index cardinality parity
SELECT (SELECT COUNT(*) FROM decision_records) AS record_count,
       (SELECT COUNT(*) FROM merkle_leaves) AS leaf_count;

-- Latest checkpoint
SELECT tree_size, root_hash, created_at
FROM merkle_checkpoints
ORDER BY id DESC
LIMIT 1;
```

## 7. Acceptance Tests

For HA sign-off:

1. Fail active writer during sustained append load.
2. Promote passive writer and continue appends.
3. Verify no chain break and no leaf index divergence.
4. Verify checkpoint continuity across failover boundary.
5. Verify auditor bundle before/after failover in strict mode.

