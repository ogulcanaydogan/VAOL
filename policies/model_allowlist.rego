# VAOL Policy: Model Allowlist
# Only permits inference requests to approved models.
# Add or remove models from the allowed_models set.

package vaol.model_allowlist

import rego.v1

default allow := false
default decision := "deny"

# Approved models for production use
allowed_models := {
    "gpt-4o",
    "gpt-4o-mini",
    "gpt-4-turbo",
    "claude-sonnet-4-5-20250929",
    "claude-haiku-4-5-20251001",
    "claude-opus-4-6",
}

allow if {
    input.model_name in allowed_models
}

decision := "allow" if {
    allow
}

rule_ids contains "model_not_in_allowlist" if {
    not allow
}

rule_ids contains "model_allowed" if {
    allow
}

reason := sprintf("model '%s' is not in the approved allowlist", [input.model_name]) if {
    not allow
}
