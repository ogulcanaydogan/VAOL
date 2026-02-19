# VAOL Base Policy
# Validates that required fields are present in the decision record input.
# This policy is always evaluated first.

package vaol.decision

import rego.v1

default allow := false
default decision := "deny"

# Allow if all required checks pass
allow if {
    has_tenant_id
    has_model
    has_output_mode
}

decision := "allow" if {
    allow
}

decision := "deny" if {
    not allow
}

# Required field checks
has_tenant_id if {
    input.tenant_id != ""
}

has_model if {
    input.model_provider != ""
    input.model_name != ""
}

has_output_mode if {
    input.output_mode in {"hash_only", "encrypted", "plaintext"}
}

# Collect violated rules
rule_ids contains "missing_tenant_id" if {
    not has_tenant_id
}

rule_ids contains "missing_model" if {
    not has_model
}

rule_ids contains "invalid_output_mode" if {
    not has_output_mode
}

rule_ids contains "base_allow" if {
    allow
}
