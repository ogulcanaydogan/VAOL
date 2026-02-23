package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
)

// PostgresStore is a PostgreSQL-backed append-only store.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a new PostgreSQL store from a connection pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Connect creates a new PostgreSQL store by connecting to the given DSN.
func Connect(ctx context.Context, dsn string) (*PostgresStore, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing DSN: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}

	return NewPostgresStore(pool), nil
}

func (s *PostgresStore) Append(ctx context.Context, rec *StoredRecord) (int64, error) {
	envJSON, err := json.Marshal(rec.Envelope)
	if err != nil {
		return 0, fmt.Errorf("marshaling envelope: %w", err)
	}

	var seq int64
	err = s.pool.QueryRow(ctx, `
		INSERT INTO decision_records (
			request_id, tenant_id, timestamp, record_hash,
			previous_record_hash, dsse_envelope, merkle_leaf_index
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING sequence_number
	`,
		rec.RequestID, rec.TenantID, rec.Timestamp, rec.RecordHash,
		rec.PreviousRecordHash, envJSON, rec.MerkleLeafIndex,
	).Scan(&seq)

	if err != nil {
		if isDuplicateKeyError(err) {
			return 0, ErrDuplicateRequestID
		}
		return 0, fmt.Errorf("inserting record: %w", err)
	}

	return seq, nil
}

func (s *PostgresStore) GetByRequestID(ctx context.Context, requestID uuid.UUID) (*StoredRecord, error) {
	return s.queryOne(ctx, `
		SELECT sequence_number, request_id, tenant_id, timestamp, record_hash,
		       previous_record_hash, dsse_envelope, merkle_leaf_index, created_at
		FROM decision_records WHERE request_id = $1
	`, requestID)
}

func (s *PostgresStore) GetBySequence(ctx context.Context, seq int64) (*StoredRecord, error) {
	return s.queryOne(ctx, `
		SELECT sequence_number, request_id, tenant_id, timestamp, record_hash,
		       previous_record_hash, dsse_envelope, merkle_leaf_index, created_at
		FROM decision_records WHERE sequence_number = $1
	`, seq)
}

func (s *PostgresStore) GetLatest(ctx context.Context) (*StoredRecord, error) {
	return s.queryOne(ctx, `
		SELECT sequence_number, request_id, tenant_id, timestamp, record_hash,
		       previous_record_hash, dsse_envelope, merkle_leaf_index, created_at
		FROM decision_records ORDER BY sequence_number DESC LIMIT 1
	`)
}

func (s *PostgresStore) List(ctx context.Context, filter ListFilter) ([]*StoredRecord, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
		SELECT sequence_number, request_id, tenant_id, timestamp, record_hash,
		       previous_record_hash, dsse_envelope, merkle_leaf_index, created_at
		FROM decision_records WHERE 1=1
	`
	args := []any{}
	argIdx := 1

	if filter.TenantID != "" {
		query += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, filter.TenantID)
		argIdx++
	}
	if filter.After != nil {
		query += fmt.Sprintf(" AND timestamp >= $%d", argIdx)
		args = append(args, *filter.After)
		argIdx++
	}
	if filter.Before != nil {
		query += fmt.Sprintf(" AND timestamp <= $%d", argIdx)
		args = append(args, *filter.Before)
		argIdx++
	}
	if filter.Cursor > 0 {
		query += fmt.Sprintf(" AND sequence_number > $%d", argIdx)
		args = append(args, filter.Cursor)
		argIdx++
	}

	query += fmt.Sprintf(" ORDER BY sequence_number ASC LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying records: %w", err)
	}
	defer rows.Close()

	var records []*StoredRecord
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}

	return records, rows.Err()
}

func (s *PostgresStore) Count(ctx context.Context) (int64, error) {
	var count int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM decision_records`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting records: %w", err)
	}
	return count, nil
}

func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

func (s *PostgresStore) queryOne(ctx context.Context, query string, args ...any) (*StoredRecord, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying record: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, ErrNotFound
	}

	return scanRecord(rows)
}

func scanRecord(rows pgx.Rows) (*StoredRecord, error) {
	var (
		rec     StoredRecord
		envJSON []byte
	)

	err := rows.Scan(
		&rec.SequenceNumber, &rec.RequestID, &rec.TenantID, &rec.Timestamp,
		&rec.RecordHash, &rec.PreviousRecordHash, &envJSON,
		&rec.MerkleLeafIndex, &rec.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning record: %w", err)
	}

	var env signer.Envelope
	if err := json.Unmarshal(envJSON, &env); err != nil {
		return nil, fmt.Errorf("unmarshaling envelope: %w", err)
	}
	rec.Envelope = &env

	return &rec, nil
}

func isDuplicateKeyError(err error) bool {
	// pgx wraps errors; check for unique_violation (23505)
	return err != nil && !errors.Is(err, context.DeadlineExceeded) &&
		containsString(err.Error(), "23505")
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Migrate runs the database migrations. In production, use a proper migration tool.
func (s *PostgresStore) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, migrationSQL)
	if err != nil {
		return fmt.Errorf("running migration: %w", err)
	}
	return nil
}

var migrationSQL = `
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

CREATE TABLE IF NOT EXISTS merkle_checkpoints (
    id BIGSERIAL PRIMARY KEY,
    tree_size BIGINT NOT NULL,
    root_hash TEXT NOT NULL,
    signed_checkpoint JSONB NOT NULL,
    rekor_entry_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS merkle_leaves (
    leaf_index BIGINT PRIMARY KEY,
    sequence_number BIGINT NOT NULL REFERENCES decision_records(sequence_number) ON DELETE CASCADE,
    request_id UUID NOT NULL REFERENCES decision_records(request_id) ON DELETE CASCADE,
    record_hash TEXT NOT NULL,
    leaf_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS proof_index (
    proof_id TEXT PRIMARY KEY,
    request_id UUID NOT NULL REFERENCES decision_records(request_id) ON DELETE CASCADE,
    proof_json JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

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

CREATE INDEX IF NOT EXISTS idx_records_tenant_ts ON decision_records(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_records_hash ON decision_records(record_hash);
CREATE INDEX IF NOT EXISTS idx_merkle_leaves_sequence ON merkle_leaves(sequence_number);
CREATE INDEX IF NOT EXISTS idx_proof_request_id ON proof_index(request_id);
CREATE INDEX IF NOT EXISTS idx_encrypted_retain_until ON encrypted_payloads(retain_until);
CREATE INDEX IF NOT EXISTS idx_tombstones_tenant_deleted_at ON payload_tombstones(tenant_id, deleted_at DESC);
CREATE INDEX IF NOT EXISTS idx_key_rotation_executed_at ON key_rotation_events(executed_at DESC);
`

// SaveCheckpoint persists a signed Merkle checkpoint.
func (s *PostgresStore) SaveCheckpoint(ctx context.Context, cp *StoredCheckpoint) error {
	if cp == nil || cp.Checkpoint == nil {
		return fmt.Errorf("checkpoint is required")
	}

	cpJSON, err := json.Marshal(cp.Checkpoint)
	if err != nil {
		return fmt.Errorf("marshaling checkpoint: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO merkle_checkpoints (tree_size, root_hash, signed_checkpoint, rekor_entry_id)
		VALUES ($1, $2, $3, $4)
	`, cp.TreeSize, cp.RootHash, cpJSON, cp.RekorEntryID)

	if err != nil {
		return fmt.Errorf("saving checkpoint: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetLatestCheckpoint(ctx context.Context) (*StoredCheckpoint, error) {
	var (
		treeSize     int64
		rootHash     string
		cpJSON       []byte
		rekorEntryID string
		createdAt    time.Time
	)

	err := s.pool.QueryRow(ctx, `
		SELECT tree_size, root_hash, signed_checkpoint, rekor_entry_id, created_at
		FROM merkle_checkpoints
		ORDER BY id DESC
		LIMIT 1
	`).Scan(&treeSize, &rootHash, &cpJSON, &rekorEntryID, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying latest checkpoint: %w", err)
	}

	var checkpoint merkle.Checkpoint
	if err := json.Unmarshal(cpJSON, &checkpoint); err != nil {
		return nil, fmt.Errorf("unmarshaling checkpoint: %w", err)
	}

	return &StoredCheckpoint{
		TreeSize:     treeSize,
		RootHash:     rootHash,
		Checkpoint:   &checkpoint,
		RekorEntryID: rekorEntryID,
		CreatedAt:    createdAt,
	}, nil
}

func (s *PostgresStore) SaveMerkleLeaf(ctx context.Context, leaf *StoredMerkleLeaf) error {
	if leaf == nil {
		return fmt.Errorf("leaf is required")
	}
	if leaf.RequestID == uuid.Nil {
		return fmt.Errorf("request_id is required")
	}
	if leaf.RecordHash == "" {
		return fmt.Errorf("record_hash is required")
	}
	if leaf.LeafHash == "" {
		return fmt.Errorf("leaf_hash is required")
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO merkle_leaves (leaf_index, sequence_number, request_id, record_hash, leaf_hash)
		VALUES ($1, $2, $3, $4, $5)
	`, leaf.LeafIndex, leaf.SequenceNumber, leaf.RequestID, leaf.RecordHash, leaf.LeafHash)
	if err != nil {
		if !isDuplicateKeyError(err) {
			return fmt.Errorf("saving merkle leaf: %w", err)
		}

		var existing StoredMerkleLeaf
		queryErr := s.pool.QueryRow(ctx, `
			SELECT leaf_index, sequence_number, request_id, record_hash, leaf_hash, created_at
			FROM merkle_leaves
			WHERE leaf_index = $1
		`, leaf.LeafIndex).Scan(
			&existing.LeafIndex,
			&existing.SequenceNumber,
			&existing.RequestID,
			&existing.RecordHash,
			&existing.LeafHash,
			&existing.CreatedAt,
		)
		if queryErr != nil {
			return fmt.Errorf("reading existing merkle leaf after conflict: %w", queryErr)
		}
		if existing.SequenceNumber == leaf.SequenceNumber &&
			existing.RequestID == leaf.RequestID &&
			existing.RecordHash == leaf.RecordHash &&
			existing.LeafHash == leaf.LeafHash {
			return nil
		}
		return fmt.Errorf("merkle leaf conflict at index %d", leaf.LeafIndex)
	}
	return nil
}

func (s *PostgresStore) ListMerkleLeaves(ctx context.Context, cursor int64, limit int) ([]*StoredMerkleLeaf, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 5000 {
		limit = 5000
	}

	rows, err := s.pool.Query(ctx, `
		SELECT leaf_index, sequence_number, request_id, record_hash, leaf_hash, created_at
		FROM merkle_leaves
		WHERE leaf_index > $1
		ORDER BY leaf_index ASC
		LIMIT $2
	`, cursor, limit)
	if err != nil {
		return nil, fmt.Errorf("querying merkle leaves: %w", err)
	}
	defer rows.Close()

	out := make([]*StoredMerkleLeaf, 0, limit)
	for rows.Next() {
		var leaf StoredMerkleLeaf
		if err := rows.Scan(
			&leaf.LeafIndex,
			&leaf.SequenceNumber,
			&leaf.RequestID,
			&leaf.RecordHash,
			&leaf.LeafHash,
			&leaf.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning merkle leaf: %w", err)
		}
		out = append(out, &leaf)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CountMerkleLeaves(ctx context.Context) (int64, error) {
	var count int64
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM merkle_leaves`).Scan(&count); err != nil {
		return 0, fmt.Errorf("counting merkle leaves: %w", err)
	}
	return count, nil
}

func (s *PostgresStore) SaveProof(ctx context.Context, proof *StoredProof) error {
	if proof == nil || proof.Proof == nil || proof.ProofID == "" {
		return fmt.Errorf("proof_id and proof are required")
	}

	proofJSON, err := json.Marshal(proof.Proof)
	if err != nil {
		return fmt.Errorf("marshaling proof: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO proof_index (proof_id, request_id, proof_json)
		VALUES ($1, $2, $3)
	`, proof.ProofID, proof.RequestID, proofJSON)
	if err != nil {
		return fmt.Errorf("saving proof: %w", err)
	}

	return nil
}

func (s *PostgresStore) GetProofByID(ctx context.Context, proofID string) (*StoredProof, error) {
	var (
		requestID uuid.UUID
		proofJSON []byte
		createdAt time.Time
	)

	err := s.pool.QueryRow(ctx, `
		SELECT request_id, proof_json, created_at
		FROM proof_index
		WHERE proof_id = $1
	`, proofID).Scan(&requestID, &proofJSON, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying proof: %w", err)
	}

	var proof merkle.Proof
	if err := json.Unmarshal(proofJSON, &proof); err != nil {
		return nil, fmt.Errorf("unmarshaling proof: %w", err)
	}

	return &StoredProof{
		ProofID:   proofID,
		RequestID: requestID,
		Proof:     &proof,
		CreatedAt: createdAt,
	}, nil
}

func (s *PostgresStore) PutEncryptedPayload(ctx context.Context, payload *EncryptedPayload) error {
	if payload == nil {
		return fmt.Errorf("payload is required")
	}
	if payload.RequestID == uuid.Nil {
		return fmt.Errorf("request_id is required")
	}
	if payload.EncryptionKeyID == "" {
		return fmt.Errorf("encryption_key_id is required")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO encrypted_payloads (
			request_id, tenant_id, encrypted_prompt, encrypted_output,
			encryption_key_id, ciphertext_hash, plaintext_hash, retain_until, rotated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (request_id) DO UPDATE SET
			tenant_id = EXCLUDED.tenant_id,
			encrypted_prompt = EXCLUDED.encrypted_prompt,
			encrypted_output = EXCLUDED.encrypted_output,
			encryption_key_id = EXCLUDED.encryption_key_id,
			ciphertext_hash = EXCLUDED.ciphertext_hash,
			plaintext_hash = EXCLUDED.plaintext_hash,
			retain_until = EXCLUDED.retain_until,
			rotated_at = EXCLUDED.rotated_at
	`, payload.RequestID, payload.TenantID, payload.EncryptedPrompt, payload.EncryptedOutput,
		payload.EncryptionKeyID, payload.CiphertextHash, payload.PlaintextHash, payload.RetainUntil, payload.RotatedAt)
	if err != nil {
		return fmt.Errorf("upserting encrypted payload: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetEncryptedPayload(ctx context.Context, requestID uuid.UUID) (*EncryptedPayload, error) {
	var (
		p          EncryptedPayload
		retainTill *time.Time
		rotatedAt  *time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT request_id, tenant_id, encrypted_prompt, encrypted_output, encryption_key_id,
		       ciphertext_hash, plaintext_hash, retain_until, rotated_at, created_at
		FROM encrypted_payloads WHERE request_id = $1
	`, requestID).Scan(
		&p.RequestID, &p.TenantID, &p.EncryptedPrompt, &p.EncryptedOutput, &p.EncryptionKeyID,
		&p.CiphertextHash, &p.PlaintextHash, &retainTill, &rotatedAt, &p.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying encrypted payload: %w", err)
	}
	p.RetainUntil = retainTill
	p.RotatedAt = rotatedAt
	return &p, nil
}

func (s *PostgresStore) DeleteExpiredEncryptedPayloads(ctx context.Context, before time.Time, limit int, reason string) ([]*PayloadTombstone, error) {
	if limit <= 0 {
		limit = 100
	}
	if reason == "" {
		reason = "retention_expired"
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	rows, err := tx.Query(ctx, `
		SELECT request_id, tenant_id, ciphertext_hash, encryption_key_id
		FROM encrypted_payloads
		WHERE retain_until IS NOT NULL AND retain_until <= $1
		ORDER BY retain_until ASC
		LIMIT $2
	`, before, limit)
	if err != nil {
		return nil, fmt.Errorf("querying expired payloads: %w", err)
	}
	defer rows.Close()

	out := make([]*PayloadTombstone, 0, limit)
	for rows.Next() {
		var (
			requestID      uuid.UUID
			tenantID       string
			ciphertextHash string
			encryptionKey  string
		)
		if err := rows.Scan(&requestID, &tenantID, &ciphertextHash, &encryptionKey); err != nil {
			return nil, fmt.Errorf("scanning expired payload row: %w", err)
		}

		ts := &PayloadTombstone{
			TombstoneID:     "tombstone:" + uuid.NewString(),
			RequestID:       requestID,
			TenantID:        tenantID,
			CiphertextHash:  ciphertextHash,
			EncryptionKeyID: encryptionKey,
			DeletedAt:       before.UTC(),
			DeleteReason:    reason,
			CreatedAt:       time.Now().UTC(),
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO payload_tombstones (
				tombstone_id, request_id, tenant_id, ciphertext_hash, encryption_key_id,
				deleted_at, delete_reason, created_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		`, ts.TombstoneID, ts.RequestID, ts.TenantID, ts.CiphertextHash, ts.EncryptionKeyID,
			ts.DeletedAt, ts.DeleteReason, ts.CreatedAt); err != nil {
			return nil, fmt.Errorf("inserting tombstone: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM encrypted_payloads WHERE request_id = $1`, requestID); err != nil {
			return nil, fmt.Errorf("deleting expired payload: %w", err)
		}
		out = append(out, ts)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating expired payload rows: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing retention transaction: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) RotateEncryptionKeyMetadata(ctx context.Context, oldKeyID, newKeyID string, limit int) (int64, error) {
	if oldKeyID == "" || newKeyID == "" {
		return 0, fmt.Errorf("old and new key IDs are required")
	}
	if limit <= 0 {
		limit = 1000
	}

	tag, err := s.pool.Exec(ctx, `
		WITH target AS (
			SELECT ctid
			FROM encrypted_payloads
			WHERE encryption_key_id = $1
			ORDER BY created_at ASC
			LIMIT $2
		)
		UPDATE encrypted_payloads e
		SET encryption_key_id = $3,
		    rotated_at = NOW()
		FROM target
		WHERE e.ctid = target.ctid
	`, oldKeyID, limit, newKeyID)
	if err != nil {
		return 0, fmt.Errorf("rotating payload key metadata: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (s *PostgresStore) ListPayloadTombstones(ctx context.Context, tenantID string, limit int) ([]*PayloadTombstone, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT tombstone_id, request_id, tenant_id, ciphertext_hash, encryption_key_id,
		       deleted_at, delete_reason, created_at
		FROM payload_tombstones
	`
	args := []any{}
	if tenantID != "" {
		query += ` WHERE tenant_id = $1`
		args = append(args, tenantID)
		query += ` ORDER BY deleted_at DESC LIMIT $2`
		args = append(args, limit)
	} else {
		query += ` ORDER BY deleted_at DESC LIMIT $1`
		args = append(args, limit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying payload tombstones: %w", err)
	}
	defer rows.Close()

	out := make([]*PayloadTombstone, 0, limit)
	for rows.Next() {
		var ts PayloadTombstone
		if err := rows.Scan(
			&ts.TombstoneID, &ts.RequestID, &ts.TenantID, &ts.CiphertextHash, &ts.EncryptionKeyID,
			&ts.DeletedAt, &ts.DeleteReason, &ts.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning payload tombstone: %w", err)
		}
		out = append(out, &ts)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SaveKeyRotationEvent(ctx context.Context, event *KeyRotationEvent) error {
	if event == nil {
		return fmt.Errorf("event is required")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO key_rotation_events (
			event_id, old_key_id, new_key_id, updated_count, executed_at, evidence_hash, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, event.EventID, event.OldKeyID, event.NewKeyID, event.UpdatedCount, event.ExecutedAt, event.EvidenceHash, event.CreatedAt)
	if err != nil {
		return fmt.Errorf("saving key rotation event: %w", err)
	}
	return nil
}

func (s *PostgresStore) ListKeyRotationEvents(ctx context.Context, limit int) ([]*KeyRotationEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT event_id, old_key_id, new_key_id, updated_count, executed_at, evidence_hash, created_at
		FROM key_rotation_events
		ORDER BY executed_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("querying key rotation events: %w", err)
	}
	defer rows.Close()

	out := make([]*KeyRotationEvent, 0, limit)
	for rows.Next() {
		var evt KeyRotationEvent
		if err := rows.Scan(&evt.EventID, &evt.OldKeyID, &evt.NewKeyID, &evt.UpdatedCount, &evt.ExecutedAt, &evt.EvidenceHash, &evt.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning key rotation event: %w", err)
		}
		out = append(out, &evt)
	}
	return out, rows.Err()
}
