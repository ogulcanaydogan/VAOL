# VAOL Policy: PHI/PII Redaction Required
# For healthcare tenants, requires that PHI redaction transforms
# are applied before storage.

package vaol.phi_redaction

import rego.v1

default allow := true
default decision := "allow"

# Healthcare tenants that require PHI redaction
healthcare_tenants := {
    "acme-health",
    "medcorp",
    "hospital-system",
}

# Check if this tenant requires PHI redaction
requires_redaction if {
    input.tenant_id in healthcare_tenants
}

# Deny if healthcare tenant but no redaction
allow := false if {
    requires_redaction
    not has_redaction_transform
}

decision := "deny" if {
    not allow
}

decision := "allow_with_transform" if {
    requires_redaction
    allow
}

has_redaction_transform if {
    some transform in input.transforms_applied
    transform.type in {"redact_phi", "redact_pii"}
}

rule_ids contains "phi_redaction_required" if {
    requires_redaction
    not has_redaction_transform
}

rule_ids contains "phi_redaction_present" if {
    requires_redaction
    has_redaction_transform
}

reason := "PHI/PII redaction is required for healthcare tenants" if {
    requires_redaction
    not allow
}
