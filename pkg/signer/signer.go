// Package signer provides DSSE envelope creation and cryptographic signing
// for VAOL DecisionRecords. Supports Ed25519 (local), Sigstore (keyless), and KMS/HSM.
package signer

import (
	"context"
	"fmt"
	"time"
)

// PayloadType is the DSSE payload type for VAOL DecisionRecords.
const PayloadType = "application/vnd.vaol.decision-record.v1+json"

// Envelope is a Dead Simple Signing Envelope (DSSE) per the specification.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature represents a single signature within a DSSE envelope.
type Signature struct {
	KeyID        string `json:"keyid"`
	Sig          string `json:"sig"`
	Cert         string `json:"cert,omitempty"`
	RekorEntryID string `json:"rekor_entry_id,omitempty"`
	Timestamp    string `json:"timestamp,omitempty"`
}

// Signer is the interface for signing DSSE payloads.
type Signer interface {
	// Sign signs the given payload bytes and returns a Signature.
	Sign(ctx context.Context, payload []byte) (Signature, error)

	// KeyID returns the identifier for this signer's key.
	KeyID() string

	// Algorithm returns the signing algorithm name (e.g., "ed25519", "sigstore-keyless").
	Algorithm() string
}

// Verifier is the interface for verifying DSSE signatures.
type Verifier interface {
	// Verify checks that the signature is valid for the given payload.
	Verify(ctx context.Context, payload []byte, sig Signature) error

	// KeyID returns the expected key identifier.
	KeyID() string
}

// SignEnvelope creates a DSSE envelope by signing the payload with the given signer(s).
func SignEnvelope(ctx context.Context, payload []byte, signers ...Signer) (*Envelope, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("at least one signer is required")
	}

	// DSSE PAE (Pre-Authentication Encoding)
	pae := PAE(PayloadType, payload)

	env := &Envelope{
		PayloadType: PayloadType,
		Payload:     b64Encode(payload),
		Signatures:  make([]Signature, 0, len(signers)),
	}

	for _, s := range signers {
		sig, err := s.Sign(ctx, pae)
		if err != nil {
			return nil, fmt.Errorf("signing with %s: %w", s.KeyID(), err)
		}
		if sig.Timestamp == "" {
			sig.Timestamp = time.Now().UTC().Format(time.RFC3339)
		}
		env.Signatures = append(env.Signatures, sig)
	}

	return env, nil
}

// VerifyEnvelope verifies all signatures in a DSSE envelope.
func VerifyEnvelope(ctx context.Context, env *Envelope, verifiers ...Verifier) error {
	if len(env.Signatures) == 0 {
		return fmt.Errorf("envelope has no signatures")
	}

	payload, err := b64Decode(env.Payload)
	if err != nil {
		return fmt.Errorf("decoding payload: %w", err)
	}

	pae := PAE(env.PayloadType, payload)

	verified := 0
	for _, sig := range env.Signatures {
		for _, v := range verifiers {
			if err := v.Verify(ctx, pae, sig); err == nil {
				verified++
				break
			}
		}
	}

	if verified == 0 {
		return fmt.Errorf("no signatures could be verified")
	}

	return nil
}

// ExtractPayload decodes and returns the raw payload from a DSSE envelope.
func ExtractPayload(env *Envelope) ([]byte, error) {
	return b64Decode(env.Payload)
}

// PAE implements DSSE Pre-Authentication Encoding.
// PAE(payloadType, payload) = "DSSEv1" + SP + len(payloadType) + SP + payloadType + SP + len(payload) + SP + payload
func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s",
		len(payloadType), payloadType,
		len(payload), payload,
	))
}
