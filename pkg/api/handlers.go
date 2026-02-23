package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
	"github.com/ogulcanaydogan/vaol/pkg/export"
	"github.com/ogulcanaydogan/vaol/pkg/ingest"
	"github.com/ogulcanaydogan/vaol/pkg/merkle"
	"github.com/ogulcanaydogan/vaol/pkg/policy"
	"github.com/ogulcanaydogan/vaol/pkg/record"
	"github.com/ogulcanaydogan/vaol/pkg/signer"
	"github.com/ogulcanaydogan/vaol/pkg/store"
	"github.com/ogulcanaydogan/vaol/pkg/verifier"
)

type verifyEnvelopeRequest struct {
	Envelope            *signer.Envelope `json:"envelope"`
	VerificationProfile string           `json:"verification_profile"`
}

type verifyBundleRequest struct {
	Bundle              *export.Bundle `json:"bundle"`
	VerificationProfile string         `json:"verification_profile"`
}

func (s *Server) handleAppendRecord(w http.ResponseWriter, r *http.Request) {
	var rec record.DecisionRecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: %v", err)
		return
	}

	// Set defaults
	if rec.SchemaVersion == "" {
		rec.SchemaVersion = record.SchemaVersion
	}
	if rec.RequestID.String() == "00000000-0000-0000-0000-000000000000" {
		rec.RequestID = uuid.New()
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}

	tenantHeader, tenantErr := tenantContextFromRequestValidated(r)
	if tenantErr != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": tenantErr.Error(),
			"decision": map[string]any{
				"decision":             "deny",
				"allow":                false,
				"decision_reason_code": "tenant_context_conflict",
				"rule_ids":             []string{"tenant_binding"},
			},
		})
		return
	}
	if tenantHeader != "" {
		if rec.Identity.TenantID == "" {
			rec.Identity.TenantID = tenantHeader
		} else if rec.Identity.TenantID != tenantHeader {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "tenant mismatch between request body and authenticated context",
				"decision": map[string]any{
					"decision":             "deny",
					"allow":                false,
					"decision_reason_code": "tenant_mismatch",
					"rule_ids":             []string{"tenant_binding"},
				},
			})
			return
		}
	}

	authIssuer := r.Header.Get("X-Auth-Issuer")
	authSubject := r.Header.Get("X-Auth-Subject")
	authSource := r.Header.Get("X-Auth-Source")
	authTokenHash := r.Header.Get("X-Auth-Token-Hash")
	authz := r.Header.Get("Authorization")
	if authIssuer != "" || authSubject != "" || authSource != "" || authz != "" {
		rec.AuthContext = &record.AuthContext{
			Issuer:        authIssuer,
			Subject:       authSubject,
			Source:        authSource,
			Authenticated: authSubject != "" || authz != "",
		}
		if authTokenHash != "" {
			rec.AuthContext.TokenHash = authTokenHash
		} else if authz != "" {
			rec.AuthContext.TokenHash = vaolcrypto.SHA256Prefixed([]byte(authz))
		}
		if authSubject != "" {
			if rec.Identity.Subject == "" {
				rec.Identity.Subject = authSubject
			} else if rec.Identity.Subject != authSubject {
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error": "subject mismatch between request body and authenticated context",
					"decision": map[string]any{
						"decision":             "deny",
						"allow":                false,
						"decision_reason_code": "subject_mismatch",
						"rule_ids":             []string{"subject_binding"},
					},
				})
				return
			}
		}
	}

	// Policy evaluation
	if s.policy != nil {
		policyInput := &policy.Input{
			TenantID:      rec.Identity.TenantID,
			SubjectType:   rec.Identity.SubjectType,
			ModelProvider: rec.Model.Provider,
			ModelName:     rec.Model.Name,
			OutputMode:    string(rec.Output.Mode),
			HasRAGContext: rec.RAGContext != nil,
			HasCitations:  rec.RAGContext != nil && len(rec.RAGContext.CitationHashes) > 0,
		}

		decision, err := s.policy.Evaluate(r.Context(), policyInput)
		if err != nil {
			s.logger.Error("policy evaluation failed", "error", err)
			writeError(w, http.StatusInternalServerError, "policy evaluation failed")
			return
		}

		rec.PolicyContext.PolicyDecision = record.PolicyDecision(decision.Decision)
		rec.PolicyContext.DecisionReasonCode = decision.DecisionReasonCode
		rec.PolicyContext.RuleIDs = decision.RuleIDs
		rec.PolicyContext.PolicyHash = s.policy.PolicyHash()
		rec.PolicyContext.PolicyBundleID = s.policy.PolicyBundleID()
		rec.PolicyContext.PolicyEngineVersion = s.policy.Version()

		if !decision.Allow && decision.Decision == "deny" {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":                "request denied by policy",
				"decision":             decision,
				"decision_reason_code": decision.DecisionReasonCode,
			})
			return
		}
	}

	// Compute record hash (excludes integrity computed fields)
	recordHash, err := record.ComputeRecordHash(&rec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "computing record hash: %v", err)
		return
	}
	rec.Integrity.RecordHash = recordHash

	// Hash chain: get previous record hash
	latest, err := s.store.GetLatest(r.Context())
	if err != nil {
		if err == store.ErrNotFound {
			rec.Integrity.PreviousRecordHash = vaolcrypto.ZeroHash
		} else {
			writeError(w, http.StatusInternalServerError, "getting latest record: %v", err)
			return
		}
	} else {
		rec.Integrity.PreviousRecordHash = latest.RecordHash
	}

	// Append to Merkle tree
	leafIndex := s.tree.Append([]byte(recordHash))
	treeSize := s.tree.Size()
	merkleRoot := s.tree.Root()

	rec.Integrity.MerkleTreeSize = treeSize
	rec.Integrity.MerkleRoot = merkleRoot

	// Get inclusion proof
	proof, err := s.tree.InclusionProof(leafIndex, treeSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generating inclusion proof: %v", err)
		return
	}
	rec.Integrity.InclusionProof = &record.InclusionProof{
		LeafIndex: proof.LeafIndex,
		Hashes:    proof.Hashes,
	}
	proofID := proofIDForRequestID(rec.RequestID)
	rec.Integrity.InclusionProofRef = fmt.Sprintf("/v1/proofs/%s", proofID)

	if err := record.Validate(&rec); err != nil {
		writeError(w, http.StatusBadRequest, "invalid decision record: %v", err)
		return
	}

	// Sign after Merkle fields are populated so the signed payload includes
	// full integrity evidence (except sequence number, which is assigned by store).
	fullPayload, err := json.Marshal(&rec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "marshaling record: %v", err)
		return
	}

	env, err := signer.SignEnvelope(r.Context(), fullPayload, s.signer)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing record: %v", err)
		return
	}

	// Store the signed record
	stored := &store.StoredRecord{
		RequestID:          rec.RequestID,
		TenantID:           rec.Identity.TenantID,
		Timestamp:          rec.Timestamp,
		RecordHash:         recordHash,
		PreviousRecordHash: rec.Integrity.PreviousRecordHash,
		Envelope:           env,
		MerkleLeafIndex:    leafIndex,
	}

	seq, err := s.store.Append(r.Context(), stored)
	if err != nil {
		if err == store.ErrDuplicateRequestID {
			writeError(w, http.StatusConflict, "duplicate request_id")
			return
		}
		writeError(w, http.StatusInternalServerError, "storing record: %v", err)
		return
	}

	rec.Integrity.SequenceNumber = seq

	if leafErr := s.persistMerkleLeaf(r.Context(), rec.RequestID, seq, leafIndex, recordHash); leafErr != nil {
		s.logger.Warn("failed to persist Merkle leaf state", "request_id", rec.RequestID.String(), "leaf_index", leafIndex, "error", leafErr)
	}

	// Persist proof after record append for stores that enforce request_id FK.
	// If proof persistence fails, the record is still valid and proof can be
	// reconstructed via /v1/records/{id}/proof and proof-id fallback logic.
	if err := s.store.SaveProof(r.Context(), &store.StoredProof{
		ProofID:   proofID,
		RequestID: rec.RequestID,
		Proof:     proof,
	}); err != nil {
		s.logger.Warn("failed to persist inclusion proof", "request_id", rec.RequestID.String(), "proof_id", proofID, "error", err)
	}

	if err := s.maybePersistCheckpoint(r.Context(), seq); err != nil {
		writeError(w, http.StatusInternalServerError, "persisting checkpoint: %v", err)
		return
	}
	if err := s.publishDecisionRecordEvent(r.Context(), &rec); err != nil {
		s.logger.Warn("failed to publish ingest event",
			"request_id", rec.RequestID.String(),
			"sequence_number", seq,
			"error", err,
		)
	}

	// Return receipt
	receipt := record.Receipt{
		RequestID:         rec.RequestID,
		SequenceNumber:    seq,
		RecordHash:        recordHash,
		MerkleRoot:        merkleRoot,
		MerkleTreeSize:    treeSize,
		InclusionProofRef: rec.Integrity.InclusionProofRef,
		InclusionProof:    rec.Integrity.InclusionProof,
		Timestamp:         rec.Timestamp,
	}

	w.Header().Set("X-VAOL-Record-ID", rec.RequestID.String())
	w.Header().Set("X-VAOL-Sequence", fmt.Sprintf("%d", seq))
	writeJSON(w, http.StatusCreated, receipt)
}

func (s *Server) persistMerkleLeaf(
	ctx context.Context,
	requestID uuid.UUID,
	sequenceNumber int64,
	leafIndex int64,
	recordHash string,
) error {
	leafStore, ok := s.store.(store.MerkleLeafStore)
	if !ok {
		return nil
	}
	leafHash := vaolcrypto.BytesToHash(vaolcrypto.MerkleLeafHash([]byte(recordHash)))
	return leafStore.SaveMerkleLeaf(ctx, &store.StoredMerkleLeaf{
		LeafIndex:      leafIndex,
		SequenceNumber: sequenceNumber,
		RequestID:      requestID,
		RecordHash:     recordHash,
		LeafHash:       leafHash,
	})
}

func (s *Server) handleGetRecord(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	reqID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request ID: %v", err)
		return
	}

	stored, err := s.store.GetByRequestID(r.Context(), reqID)
	if err != nil {
		if err == store.ErrNotFound {
			writeError(w, http.StatusNotFound, "record not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "retrieving record: %v", err)
		return
	}

	if !enforceTenantAccess(w, r, stored.TenantID) {
		return
	}

	writeJSON(w, http.StatusOK, stored)
}

func (s *Server) handleListRecords(w http.ResponseWriter, r *http.Request) {
	requestedTenant := r.URL.Query().Get("tenant_id")
	tenantID, ok := enforceTenantFilter(w, r, requestedTenant)
	if !ok {
		return
	}

	filter := store.ListFilter{
		TenantID: tenantID,
		Limit:    100,
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			filter.Limit = l
		}
	}
	if cursorStr := r.URL.Query().Get("cursor"); cursorStr != "" {
		if c, err := strconv.ParseInt(cursorStr, 10, 64); err == nil {
			filter.Cursor = c
		}
	}
	if afterStr := r.URL.Query().Get("after"); afterStr != "" {
		if t, err := time.Parse(time.RFC3339, afterStr); err == nil {
			filter.After = &t
		}
	}
	if beforeStr := r.URL.Query().Get("before"); beforeStr != "" {
		if t, err := time.Parse(time.RFC3339, beforeStr); err == nil {
			filter.Before = &t
		}
	}

	records, err := s.store.List(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing records: %v", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"records": records,
		"count":   len(records),
	})
}

func (s *Server) handleGetProof(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	reqID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request ID: %v", err)
		return
	}

	stored, err := s.store.GetByRequestID(r.Context(), reqID)
	if err != nil {
		if err == store.ErrNotFound {
			writeError(w, http.StatusNotFound, "record not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "retrieving record: %v", err)
		return
	}

	if !enforceTenantAccess(w, r, stored.TenantID) {
		return
	}

	proofID := proofIDForRequestID(stored.RequestID)
	proof, err := s.store.GetProofByID(r.Context(), proofID)
	if err == nil {
		writeJSON(w, http.StatusOK, proof.Proof)
		return
	}

	// Fallback for legacy records without stored proof index.
	liveProof, liveErr := s.tree.InclusionProof(stored.MerkleLeafIndex, s.tree.Size())
	if liveErr != nil {
		writeError(w, http.StatusInternalServerError, "generating proof: %v", liveErr)
		return
	}
	writeJSON(w, http.StatusOK, liveProof)
}

func (s *Server) handleGetProofByID(w http.ResponseWriter, r *http.Request) {
	proofID := r.PathValue("id")
	if proofID == "" {
		writeError(w, http.StatusBadRequest, "proof ID is required")
		return
	}

	proof, err := s.store.GetProofByID(r.Context(), proofID)
	if err != nil {
		if err != store.ErrNotFound {
			writeError(w, http.StatusInternalServerError, "retrieving proof: %v", err)
			return
		}

		// Fallback: derive request_id from canonical proof ID format and
		// reconstruct proof from current tree.
		requestIDRaw := strings.TrimPrefix(proofID, "proof:")
		requestID, parseErr := uuid.Parse(requestIDRaw)
		if parseErr != nil {
			writeError(w, http.StatusNotFound, "proof not found")
			return
		}

		stored, recErr := s.store.GetByRequestID(r.Context(), requestID)
		if recErr != nil {
			if recErr == store.ErrNotFound {
				writeError(w, http.StatusNotFound, "record for proof not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "retrieving record for proof: %v", recErr)
			return
		}

		if !enforceTenantAccess(w, r, stored.TenantID) {
			return
		}

		liveProof, liveErr := s.tree.InclusionProof(stored.MerkleLeafIndex, s.tree.Size())
		if liveErr != nil {
			writeError(w, http.StatusInternalServerError, "generating proof: %v", liveErr)
			return
		}
		writeJSON(w, http.StatusOK, liveProof)
		return
	}

	stored, err := s.store.GetByRequestID(r.Context(), proof.RequestID)
	if err != nil {
		if err == store.ErrNotFound {
			writeError(w, http.StatusNotFound, "record for proof not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "retrieving record for proof: %v", err)
		return
	}

	if !enforceTenantAccess(w, r, stored.TenantID) {
		return
	}

	writeJSON(w, http.StatusOK, proof.Proof)
}

func (s *Server) handleVerifyRecord(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "reading request body: %v", err)
		return
	}

	env, profileFromBody, err := decodeVerifyEnvelopeRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid envelope: %v", err)
		return
	}

	profile, err := resolveVerificationProfile(r.URL.Query().Get("profile"), profileFromBody)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid verification profile: %v", err)
		return
	}

	result, err := s.verifier.VerifyEnvelopeWithProfile(r.Context(), env, profile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verification error: %v", err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleVerifyBundle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "reading request body: %v", err)
		return
	}

	bundle, profileFromBody, err := decodeVerifyBundleRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid bundle: %v", err)
		return
	}

	profile, err := resolveVerificationProfile(r.URL.Query().Get("profile"), profileFromBody)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid verification profile: %v", err)
		return
	}

	result, err := s.verifier.VerifyBundle(r.Context(), bundle, profile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "bundle verification error: %v", err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func decodeVerifyEnvelopeRequest(body []byte) (*signer.Envelope, string, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, "", fmt.Errorf("request body is empty")
	}

	var req verifyEnvelopeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", err
	}
	if req.Envelope != nil {
		return req.Envelope, req.VerificationProfile, nil
	}

	var env signer.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, "", err
	}
	if env.PayloadType == "" && env.Payload == "" && len(env.Signatures) == 0 {
		return nil, req.VerificationProfile, fmt.Errorf("missing envelope")
	}
	return &env, req.VerificationProfile, nil
}

func decodeVerifyBundleRequest(body []byte) (*export.Bundle, string, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, "", fmt.Errorf("request body is empty")
	}

	var req verifyBundleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", err
	}
	if req.Bundle != nil {
		return req.Bundle, req.VerificationProfile, nil
	}

	var bundle export.Bundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return nil, "", err
	}
	return &bundle, req.VerificationProfile, nil
}

func resolveVerificationProfile(queryProfile, bodyProfile string) (verifier.Profile, error) {
	queryProfile = strings.TrimSpace(queryProfile)
	bodyProfile = strings.TrimSpace(bodyProfile)

	switch {
	case queryProfile == "" && bodyProfile == "":
		return verifier.ProfileBasic, nil
	case queryProfile == "":
		return parseVerificationProfile(bodyProfile)
	case bodyProfile == "":
		return parseVerificationProfile(queryProfile)
	default:
		queryParsed, err := parseVerificationProfile(queryProfile)
		if err != nil {
			return "", err
		}
		bodyParsed, err := parseVerificationProfile(bodyProfile)
		if err != nil {
			return "", err
		}
		if queryParsed != bodyParsed {
			return "", fmt.Errorf("conflicting profile values: query=%q body=%q", queryProfile, bodyProfile)
		}
		return queryParsed, nil
	}
}

func parseVerificationProfile(raw string) (verifier.Profile, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(verifier.ProfileBasic):
		return verifier.ProfileBasic, nil
	case string(verifier.ProfileStrict):
		return verifier.ProfileStrict, nil
	case string(verifier.ProfileFIPS):
		return verifier.ProfileFIPS, nil
	default:
		return "", fmt.Errorf("unsupported profile %q", raw)
	}
}

func (s *Server) handleGetCheckpoint(w http.ResponseWriter, r *http.Request) {
	checkpoint, err := s.store.GetLatestCheckpoint(r.Context())
	if err == nil {
		writeJSON(w, http.StatusOK, checkpoint.Checkpoint)
		return
	}

	// Fallback for deployments with no persisted checkpoints yet.
	size := s.tree.Size()
	root := s.tree.Root()
	writeJSON(w, http.StatusOK, &merkle.Checkpoint{
		TreeSize:  size,
		RootHash:  root,
		Timestamp: time.Now().UTC(),
	})
}

func (s *Server) handleGetConsistencyProof(w http.ResponseWriter, r *http.Request) {
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		writeError(w, http.StatusBadRequest, "from and to query parameters are required")
		return
	}

	from, err := strconv.ParseInt(fromStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid from value: %v", err)
		return
	}
	to, err := strconv.ParseInt(toStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid to value: %v", err)
		return
	}

	proof, err := s.tree.ConsistencyProof(from, to)
	if err != nil {
		writeError(w, http.StatusBadRequest, "generating consistency proof: %v", err)
		return
	}

	writeJSON(w, http.StatusOK, proof)
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TenantID string `json:"tenant_id"`
		After    string `json:"after"`
		Before   string `json:"before"`
		Limit    int    `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid export request: %v", err)
		return
	}

	tenantID, ok := enforceTenantFilter(w, r, req.TenantID)
	if !ok {
		return
	}
	req.TenantID = tenantID

	filter := store.ListFilter{
		TenantID: req.TenantID,
		Limit:    req.Limit,
	}
	if filter.Limit <= 0 {
		filter.Limit = 1000
	}
	if req.After != "" {
		if t, err := time.Parse(time.RFC3339, req.After); err == nil {
			filter.After = &t
		}
	}
	if req.Before != "" {
		if t, err := time.Parse(time.RFC3339, req.Before); err == nil {
			filter.Before = &t
		}
	}

	records, err := s.store.List(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing records: %v", err)
		return
	}

	bundleFilter := export.BundleFilter{
		TenantID: req.TenantID,
	}
	bundle := export.NewBundle(bundleFilter)

	for _, stored := range records {
		proofID := proofIDForRequestID(stored.RequestID)
		var proof *merkle.Proof
		if persistedProof, err := s.store.GetProofByID(r.Context(), proofID); err == nil {
			proof = persistedProof.Proof
		} else {
			// Backward-compatible fallback for legacy records without proof index.
			proof, _ = s.tree.InclusionProof(stored.MerkleLeafIndex, s.tree.Size())
		}
		bundle.AddRecord(export.BundleRecord{
			SequenceNumber: stored.SequenceNumber,
			Envelope:       stored.Envelope,
			InclusionProof: proof,
		})
	}

	if cp, err := s.store.GetLatestCheckpoint(r.Context()); err == nil {
		bundle.AddCheckpoint(export.BundleCheckpoint{
			Checkpoint:   cp.Checkpoint,
			RekorEntryID: cp.RekorEntryID,
		})
	}
	if tombstones, err := s.store.ListPayloadTombstones(r.Context(), req.TenantID, filter.Limit); err == nil {
		bundle.AddPayloadTombstones(tombstones)
	}
	if rotationEvents, err := s.store.ListKeyRotationEvents(r.Context(), filter.Limit); err == nil {
		bundle.AddKeyRotationEvents(rotationEvents)
	}

	bundle.Finalize()
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	count, _ := s.store.Count(context.Background())
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"version":      s.config.Version,
		"record_count": count,
		"tree_size":    s.tree.Size(),
	})
}

func (s *Server) maybePersistCheckpoint(ctx context.Context, seq int64) error {
	s.checkpointMu.Lock()
	defer s.checkpointMu.Unlock()

	intervalRecords := s.config.CheckpointEvery
	if intervalRecords <= 0 {
		intervalRecords = 100
	}
	intervalTime := s.config.CheckpointInterval
	if intervalTime <= 0 {
		intervalTime = 5 * time.Minute
	}

	now := time.Now().UTC()
	shouldPersist := seq == 0 || (seq+1)%intervalRecords == 0 || now.Sub(s.lastCheckpointAt) >= intervalTime
	if !shouldPersist {
		return nil
	}

	cp, err := s.checkpointSigner.SignCheckpoint(ctx, s.tree)
	if err != nil {
		return fmt.Errorf("signing checkpoint: %w", err)
	}

	if s.anchorClient != nil {
		entryID, anchorErr := s.anchorClient.Anchor(ctx, cp)
		if anchorErr != nil {
			// Deterministic fail-closed for anchoring: preserve checkpoint but
			// surface error so caller can decide policy behavior.
			return fmt.Errorf("anchoring checkpoint: %w", anchorErr)
		}
		cp.RekorEntryID = entryID
	}

	if err := s.store.SaveCheckpoint(ctx, &store.StoredCheckpoint{
		TreeSize:     cp.TreeSize,
		RootHash:     cp.RootHash,
		Checkpoint:   cp,
		RekorEntryID: cp.RekorEntryID,
	}); err != nil {
		return fmt.Errorf("saving checkpoint: %w", err)
	}

	s.lastCheckpointAt = now
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		http.Error(w, `{"error":"failed to encode response"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, map[string]string{
		"error": fmt.Sprintf(format, args...),
	})
}

func tenantContextFromRequestValidated(r *http.Request) (string, error) {
	vaolTenant := strings.TrimSpace(r.Header.Get("X-VAOL-Tenant-ID"))
	legacyTenant := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	if vaolTenant != "" && legacyTenant != "" && vaolTenant != legacyTenant {
		return "", fmt.Errorf("conflicting tenant context headers")
	}
	if vaolTenant != "" {
		return vaolTenant, nil
	}
	if legacyTenant != "" {
		return legacyTenant, nil
	}
	return "", nil
}

func enforceTenantAccess(w http.ResponseWriter, r *http.Request, targetTenant string) bool {
	callerTenant, err := tenantContextFromRequestValidated(r)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": err.Error(),
			"decision": map[string]any{
				"decision":             "deny",
				"allow":                false,
				"decision_reason_code": "tenant_context_conflict",
				"rule_ids":             []string{"tenant_binding"},
			},
		})
		return false
	}
	if callerTenant == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "missing tenant context",
			"decision": map[string]any{
				"decision":             "deny",
				"allow":                false,
				"decision_reason_code": "missing_tenant_context",
				"rule_ids":             []string{"tenant_binding"},
			},
		})
		return false
	}
	if targetTenant == "" || callerTenant != targetTenant {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "tenant mismatch between request context and stored record",
			"decision": map[string]any{
				"decision":             "deny",
				"allow":                false,
				"decision_reason_code": "tenant_mismatch",
				"rule_ids":             []string{"tenant_binding"},
			},
		})
		return false
	}
	return true
}

func enforceTenantFilter(w http.ResponseWriter, r *http.Request, requestedTenant string) (string, bool) {
	callerTenant, err := tenantContextFromRequestValidated(r)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": err.Error(),
			"decision": map[string]any{
				"decision":             "deny",
				"allow":                false,
				"decision_reason_code": "tenant_context_conflict",
				"rule_ids":             []string{"tenant_binding"},
			},
		})
		return "", false
	}
	if callerTenant == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "missing tenant context",
			"decision": map[string]any{
				"decision":             "deny",
				"allow":                false,
				"decision_reason_code": "missing_tenant_context",
				"rule_ids":             []string{"tenant_binding"},
			},
		})
		return "", false
	}

	if requestedTenant != "" && requestedTenant != callerTenant {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "tenant mismatch between query/body and authenticated context",
			"decision": map[string]any{
				"decision":             "deny",
				"allow":                false,
				"decision_reason_code": "tenant_mismatch",
				"rule_ids":             []string{"tenant_binding"},
			},
		})
		return "", false
	}

	return callerTenant, true
}

func proofIDForRequestID(requestID uuid.UUID) string {
	return "proof:" + requestID.String()
}

func (s *Server) publishDecisionRecordEvent(ctx context.Context, rec *record.DecisionRecord) error {
	if s.ingestPublisher == nil {
		return nil
	}
	timeout := s.config.IngestPublishTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	publishCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return s.ingestPublisher.PublishDecisionRecord(publishCtx, &ingest.DecisionRecordEvent{
		EventVersion:       "v1",
		RequestID:          rec.RequestID.String(),
		SequenceNumber:     rec.Integrity.SequenceNumber,
		TenantID:           rec.Identity.TenantID,
		Timestamp:          rec.Timestamp.UTC(),
		RecordHash:         rec.Integrity.RecordHash,
		PreviousRecordHash: rec.Integrity.PreviousRecordHash,
		MerkleRoot:         rec.Integrity.MerkleRoot,
		MerkleTreeSize:     rec.Integrity.MerkleTreeSize,
		PolicyDecision:     string(rec.PolicyContext.PolicyDecision),
		PolicyHash:         rec.PolicyContext.PolicyHash,
		ModelProvider:      rec.Model.Provider,
		ModelName:          rec.Model.Name,
		OutputMode:         string(rec.Output.Mode),
	})
}
