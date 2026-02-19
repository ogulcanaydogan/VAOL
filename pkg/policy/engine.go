// Package policy provides the OPA/Rego policy engine integration for VAOL.
// It evaluates policies at record-creation time and seals results into the evidence record.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Decision represents the outcome of a policy evaluation.
type Decision struct {
	Allow              bool              `json:"allow"`
	Decision           string            `json:"decision"` // allow, deny, allow_with_transform, log_only
	DecisionReasonCode string            `json:"decision_reason_code,omitempty"`
	RuleIDs            []string          `json:"rule_ids,omitempty"`
	TransformsApplied  []TransformAction `json:"transforms_applied,omitempty"`
	Reason             string            `json:"reason,omitempty"`
}

// TransformAction describes a data transform prescribed by policy.
type TransformAction struct {
	Type    string `json:"type"`
	Target  string `json:"target"`
	Details string `json:"details,omitempty"`
}

// Input is the data sent to OPA for policy evaluation.
type Input struct {
	TenantID      string         `json:"tenant_id"`
	SubjectType   string         `json:"subject_type"`
	ModelProvider string         `json:"model_provider"`
	ModelName     string         `json:"model_name"`
	OutputMode    string         `json:"output_mode"`
	HasRAGContext bool           `json:"has_rag_context"`
	HasCitations  bool           `json:"has_citations"`
	Parameters    map[string]any `json:"parameters,omitempty"`
}

// Engine is the interface for policy evaluation.
type Engine interface {
	// Evaluate evaluates the policy for the given input.
	Evaluate(ctx context.Context, input *Input) (*Decision, error)

	// PolicyHash returns the SHA-256 hash of the current policy bundle.
	PolicyHash() string

	// PolicyBundleID returns the identifier of the current policy bundle.
	PolicyBundleID() string

	// Version returns the policy engine version string.
	Version() string
}

// OPAEngine evaluates policies against a running OPA instance via REST API.
type OPAEngine struct {
	endpoint       string
	policyPath     string
	policyBundleID string
	policyHash     string
	client         *http.Client
}

// OPAConfig configures the OPA engine connection.
type OPAConfig struct {
	Endpoint       string        `json:"endpoint"`    // e.g., "http://localhost:8181"
	PolicyPath     string        `json:"policy_path"` // e.g., "v1/data/vaol/decision"
	PolicyBundleID string        `json:"policy_bundle_id"`
	PolicyHash     string        `json:"policy_hash"`
	Timeout        time.Duration `json:"timeout"`
}

// NewOPAEngine creates a new OPA policy engine client.
func NewOPAEngine(cfg OPAConfig) *OPAEngine {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	return &OPAEngine{
		endpoint:       cfg.Endpoint,
		policyPath:     cfg.PolicyPath,
		policyBundleID: cfg.PolicyBundleID,
		policyHash:     cfg.PolicyHash,
		client:         &http.Client{Timeout: timeout},
	}
}

func (e *OPAEngine) Evaluate(ctx context.Context, input *Input) (*Decision, error) {
	body := map[string]any{"input": input}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling OPA input: %w", err)
	}

	url := fmt.Sprintf("%s/%s", e.endpoint, e.policyPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling OPA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OPA returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Result *Decision `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding OPA response: %w", err)
	}

	if result.Result == nil {
		return nil, fmt.Errorf("OPA returned nil result")
	}

	return result.Result, nil
}

func (e *OPAEngine) PolicyHash() string     { return e.policyHash }
func (e *OPAEngine) PolicyBundleID() string { return e.policyBundleID }
func (e *OPAEngine) Version() string        { return "opa-rest/1.0" }
