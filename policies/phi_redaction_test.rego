# Tests for VAOL phi_redaction policy

package vaol.phi_redaction_test

import rego.v1

import data.vaol.phi_redaction

# -- Non-healthcare tenants --

test_allow_non_healthcare_tenant if {
	phi_redaction.allow with input as {
		"tenant_id": "generic-corp",
		"transforms_applied": [],
	}
}

test_allow_non_healthcare_no_transforms if {
	phi_redaction.allow with input as {
		"tenant_id": "tech-startup",
	}
}

# -- Healthcare tenants with redaction --

test_allow_healthcare_with_phi_redaction if {
	phi_redaction.allow with input as {
		"tenant_id": "acme-health",
		"transforms_applied": [{"type": "redact_phi", "target": "both"}],
	}
}

test_allow_healthcare_with_pii_redaction if {
	phi_redaction.allow with input as {
		"tenant_id": "medcorp",
		"transforms_applied": [{"type": "redact_pii", "target": "output"}],
	}
}

test_allow_hospital_system if {
	phi_redaction.allow with input as {
		"tenant_id": "hospital-system",
		"transforms_applied": [{"type": "redact_phi", "target": "input"}],
	}
}

# -- Healthcare tenants without redaction --

test_deny_healthcare_no_transforms if {
	not phi_redaction.allow with input as {
		"tenant_id": "acme-health",
		"transforms_applied": [],
	}
}

test_deny_healthcare_wrong_transform if {
	not phi_redaction.allow with input as {
		"tenant_id": "medcorp",
		"transforms_applied": [{"type": "mask", "target": "output"}],
	}
}

test_deny_hospital_missing_transforms if {
	not phi_redaction.allow with input as {
		"tenant_id": "hospital-system",
	}
}

# -- Decision values --

test_decision_deny_healthcare_no_redaction if {
	phi_redaction.decision == "deny" with input as {
		"tenant_id": "acme-health",
		"transforms_applied": [],
	}
}

test_decision_allow_with_transform if {
	phi_redaction.decision == "allow_with_transform" with input as {
		"tenant_id": "acme-health",
		"transforms_applied": [{"type": "redact_phi", "target": "both"}],
	}
}

test_decision_allow_non_healthcare if {
	phi_redaction.decision == "allow" with input as {
		"tenant_id": "generic-corp",
		"transforms_applied": [],
	}
}

# -- Rule IDs --

test_rule_id_redaction_required if {
	"phi_redaction_required" in phi_redaction.rule_ids with input as {
		"tenant_id": "acme-health",
		"transforms_applied": [],
	}
}

test_rule_id_redaction_present if {
	"phi_redaction_present" in phi_redaction.rule_ids with input as {
		"tenant_id": "acme-health",
		"transforms_applied": [{"type": "redact_phi", "target": "both"}],
	}
}

test_reason_present_when_denied if {
	phi_redaction.reason with input as {
		"tenant_id": "acme-health",
		"transforms_applied": [],
	}
}
