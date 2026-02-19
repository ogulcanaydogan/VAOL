package policy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
)

// mockEngine is a configurable mock policy engine for testing.
type mockEngine struct {
	decision *Decision
	err      error
}

func (m *mockEngine) Evaluate(_ context.Context, _ *Input) (*Decision, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.decision, nil
}

func (m *mockEngine) PolicyHash() string     { return "sha256:mock" }
func (m *mockEngine) PolicyBundleID() string { return "mock-bundle" }
func (m *mockEngine) Version() string        { return "mock/1.0" }

func TestFailClosedAllowPassthrough(t *testing.T) {
	inner := &mockEngine{
		decision: &Decision{Allow: true, Decision: "allow"},
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	fc := NewFailClosedEngine(inner, logger)

	d, err := fc.Evaluate(context.Background(), &Input{TenantID: "test"})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !d.Allow {
		t.Error("should pass through allow decision")
	}
	if d.Decision != "allow" {
		t.Errorf("Decision = %q, want allow", d.Decision)
	}
}

func TestFailClosedDenyPassthrough(t *testing.T) {
	inner := &mockEngine{
		decision: &Decision{Allow: false, Decision: "deny", RuleIDs: []string{"deny_rule"}},
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	fc := NewFailClosedEngine(inner, logger)

	d, err := fc.Evaluate(context.Background(), &Input{TenantID: "test"})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if d.Allow {
		t.Error("should pass through deny decision")
	}
}

func TestFailClosedOnError(t *testing.T) {
	inner := &mockEngine{
		err: fmt.Errorf("OPA unreachable"),
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	fc := NewFailClosedEngine(inner, logger)

	d, err := fc.Evaluate(context.Background(), &Input{TenantID: "test"})
	if err != nil {
		t.Fatalf("FailClosed should not return error, got: %v", err)
	}
	if d.Allow {
		t.Error("should deny when engine is unavailable")
	}
	if d.Decision != "deny" {
		t.Errorf("Decision = %q, want deny", d.Decision)
	}
	if len(d.RuleIDs) == 0 || d.RuleIDs[0] != "fail_closed" {
		t.Error("should include fail_closed rule ID")
	}
	if d.DecisionReasonCode != "policy_engine_unavailable" {
		t.Errorf("DecisionReasonCode = %q, want policy_engine_unavailable", d.DecisionReasonCode)
	}
}

func TestFailClosedDelegatesMetadata(t *testing.T) {
	inner := &mockEngine{
		decision: &Decision{Allow: true, Decision: "allow"},
	}
	fc := NewFailClosedEngine(inner, nil)

	if fc.PolicyHash() != "sha256:mock" {
		t.Errorf("PolicyHash = %q, want sha256:mock", fc.PolicyHash())
	}
	if fc.PolicyBundleID() != "mock-bundle" {
		t.Errorf("PolicyBundleID = %q, want mock-bundle", fc.PolicyBundleID())
	}
	if fc.Version() != "mock/1.0" {
		t.Errorf("Version = %q, want mock/1.0", fc.Version())
	}
}

func TestNoopEngine(t *testing.T) {
	noop := &NoopEngine{}
	d, err := noop.Evaluate(context.Background(), &Input{TenantID: "test"})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !d.Allow {
		t.Error("NoopEngine should always allow")
	}
	if d.Decision != "allow" {
		t.Errorf("Decision = %q, want allow", d.Decision)
	}
	if d.DecisionReasonCode != "no_policy_engine" {
		t.Errorf("DecisionReasonCode = %q, want no_policy_engine", d.DecisionReasonCode)
	}
}

func TestDenyAllEngine(t *testing.T) {
	deny := NewDenyAllEngine("missing_policy_engine", "policy backend not configured")
	d, err := deny.Evaluate(context.Background(), &Input{TenantID: "test"})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if d.Allow {
		t.Error("DenyAllEngine should always deny")
	}
	if d.Decision != "deny" {
		t.Errorf("Decision = %q, want deny", d.Decision)
	}
	if d.DecisionReasonCode != "missing_policy_engine" {
		t.Errorf("DecisionReasonCode = %q, want missing_policy_engine", d.DecisionReasonCode)
	}
	if len(d.RuleIDs) == 0 || d.RuleIDs[0] != "static_deny_all" {
		t.Errorf("RuleIDs = %v, want static_deny_all", d.RuleIDs)
	}
}
