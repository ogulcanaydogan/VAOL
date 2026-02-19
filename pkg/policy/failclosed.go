package policy

import (
	"context"
	"fmt"
	"log/slog"
)

// FailClosedEngine wraps a policy engine and returns a deny decision
// if the underlying engine is unavailable or returns an error.
type FailClosedEngine struct {
	inner  Engine
	logger *slog.Logger
}

// NewFailClosedEngine wraps the given engine with fail-closed semantics.
func NewFailClosedEngine(inner Engine, logger *slog.Logger) *FailClosedEngine {
	if logger == nil {
		logger = slog.Default()
	}
	return &FailClosedEngine{
		inner:  inner,
		logger: logger,
	}
}

func (e *FailClosedEngine) Evaluate(ctx context.Context, input *Input) (*Decision, error) {
	decision, err := e.inner.Evaluate(ctx, input)
	if err != nil {
		e.logger.Error("policy engine unavailable, failing closed",
			"error", err,
			"tenant_id", input.TenantID,
			"model", input.ModelName,
		)
		return &Decision{
			Allow:              false,
			Decision:           "deny",
			DecisionReasonCode: "policy_engine_unavailable",
			RuleIDs:            []string{"fail_closed"},
			Reason:             fmt.Sprintf("policy engine unavailable: %v", err),
		}, nil
	}
	return decision, nil
}

func (e *FailClosedEngine) PolicyHash() string     { return e.inner.PolicyHash() }
func (e *FailClosedEngine) PolicyBundleID() string { return e.inner.PolicyBundleID() }
func (e *FailClosedEngine) Version() string        { return e.inner.Version() }

// NoopEngine is a policy engine that always allows. Used when no policy engine is configured.
type NoopEngine struct{}

func (e *NoopEngine) Evaluate(_ context.Context, _ *Input) (*Decision, error) {
	return &Decision{
		Allow:              true,
		Decision:           "allow",
		DecisionReasonCode: "no_policy_engine",
		RuleIDs:            []string{"noop_allow_all"},
		Reason:             "no policy engine configured",
	}, nil
}

func (e *NoopEngine) PolicyHash() string     { return "" }
func (e *NoopEngine) PolicyBundleID() string { return "" }
func (e *NoopEngine) Version() string        { return "noop/1.0" }

// DenyAllEngine deterministically denies every request. Useful when policy
// evaluation is mandatory and no policy backend is configured.
type DenyAllEngine struct {
	reasonCode string
	reason     string
}

// NewDenyAllEngine creates a deny-all policy engine with deterministic reason codes.
func NewDenyAllEngine(reasonCode, reason string) *DenyAllEngine {
	if reasonCode == "" {
		reasonCode = "policy_denied"
	}
	if reason == "" {
		reason = "request denied by static policy"
	}
	return &DenyAllEngine{
		reasonCode: reasonCode,
		reason:     reason,
	}
}

func (e *DenyAllEngine) Evaluate(_ context.Context, _ *Input) (*Decision, error) {
	return &Decision{
		Allow:              false,
		Decision:           "deny",
		DecisionReasonCode: e.reasonCode,
		RuleIDs:            []string{"static_deny_all"},
		Reason:             e.reason,
	}, nil
}

func (e *DenyAllEngine) PolicyHash() string     { return "" }
func (e *DenyAllEngine) PolicyBundleID() string { return "static-deny" }
func (e *DenyAllEngine) Version() string        { return "static/1.0" }
