-- VAOL Ledger Store: Initial Schema
-- This migration creates the core append-only tables for decision records,
-- Merkle checkpoints, and encrypted payloads.

BEGIN;

-- Core records table: append-only by design.
-- The application user (vaol_app) should be REVOKE'd UPDATE and DELETE.
CREATE TABLE IF NOT EXISTS decision_records (
    sequence_number BIGSERIAL PRIMARY KEY,
    request_id UUID UNIQUE NOT NULL,
    tenant_id TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    record_hash TEXT NOT NULL,
    previous_record_hash TEXT NOT NULL,
    dsse_envelope JSONB NOT NULL,
    merkle_leaf_index BIGINT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Signed Merkle checkpoints for periodic tree state snapshots.
CREATE TABLE IF NOT EXISTS merkle_checkpoints (
    id BIGSERIAL PRIMARY KEY,
    tree_size BIGINT NOT NULL,
    root_hash TEXT NOT NULL,
    signed_checkpoint JSONB NOT NULL,
    rekor_entry_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Encrypted prompt/output blobs (used when output.mode = "encrypted").
CREATE TABLE IF NOT EXISTS encrypted_payloads (
    request_id UUID PRIMARY KEY REFERENCES decision_records(request_id),
    tenant_id TEXT NOT NULL DEFAULT '',
    encrypted_prompt BYTEA,
    encrypted_output BYTEA,
    encryption_key_id TEXT NOT NULL,
    ciphertext_hash TEXT,
    plaintext_hash TEXT,
    retain_until TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS payload_tombstones (
    tombstone_id TEXT PRIMARY KEY,
    request_id UUID NOT NULL,
    tenant_id TEXT NOT NULL,
    ciphertext_hash TEXT,
    encryption_key_id TEXT NOT NULL,
    deleted_at TIMESTAMPTZ NOT NULL,
    delete_reason TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS key_rotation_events (
    event_id TEXT PRIMARY KEY,
    old_key_id TEXT NOT NULL,
    new_key_id TEXT NOT NULL,
    updated_count BIGINT NOT NULL,
    executed_at TIMESTAMPTZ NOT NULL,
    evidence_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE encrypted_payloads ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE encrypted_payloads ADD COLUMN IF NOT EXISTS ciphertext_hash TEXT;
ALTER TABLE encrypted_payloads ADD COLUMN IF NOT EXISTS plaintext_hash TEXT;
ALTER TABLE encrypted_payloads ADD COLUMN IF NOT EXISTS retain_until TIMESTAMPTZ;
ALTER TABLE encrypted_payloads ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ;

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_records_tenant_ts ON decision_records(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_records_hash ON decision_records(record_hash);
CREATE INDEX IF NOT EXISTS idx_checkpoints_tree_size ON merkle_checkpoints(tree_size DESC);
CREATE INDEX IF NOT EXISTS idx_encrypted_retain_until ON encrypted_payloads(retain_until);
CREATE INDEX IF NOT EXISTS idx_tombstones_tenant_deleted_at ON payload_tombstones(tenant_id, deleted_at DESC);
CREATE INDEX IF NOT EXISTS idx_key_rotation_executed_at ON key_rotation_events(executed_at DESC);

-- Enforce append-only semantics at the database level.
-- Run this AFTER creating the vaol_app role:
-- REVOKE UPDATE, DELETE ON decision_records FROM vaol_app;
-- REVOKE UPDATE, DELETE ON merkle_checkpoints FROM vaol_app;
-- REVOKE UPDATE, DELETE ON payload_tombstones FROM vaol_app;

COMMIT;
