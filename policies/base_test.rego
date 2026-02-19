# Tests for VAOL base policy

package vaol.decision_test

import rego.v1

import data.vaol.decision

# -- Allow cases --

test_allow_valid_input if {
	decision.allow with input as {
		"tenant_id": "acme-corp",
		"model_provider": "openai",
		"model_name": "gpt-4o",
		"output_mode": "hash_only",
	}
}

test_allow_encrypted_mode if {
	decision.allow with input as {
		"tenant_id": "acme-corp",
		"model_provider": "anthropic",
		"model_name": "claude-sonnet-4-5-20250929",
		"output_mode": "encrypted",
	}
}

test_allow_plaintext_mode if {
	decision.allow with input as {
		"tenant_id": "acme-corp",
		"model_provider": "openai",
		"model_name": "gpt-4o",
		"output_mode": "plaintext",
	}
}

# -- Deny cases --

test_deny_missing_tenant if {
	not decision.allow with input as {
		"tenant_id": "",
		"model_provider": "openai",
		"model_name": "gpt-4o",
		"output_mode": "hash_only",
	}
}

test_deny_missing_model_provider if {
	not decision.allow with input as {
		"tenant_id": "acme-corp",
		"model_provider": "",
		"model_name": "gpt-4o",
		"output_mode": "hash_only",
	}
}

test_deny_missing_model_name if {
	not decision.allow with input as {
		"tenant_id": "acme-corp",
		"model_provider": "openai",
		"model_name": "",
		"output_mode": "hash_only",
	}
}

test_deny_invalid_output_mode if {
	not decision.allow with input as {
		"tenant_id": "acme-corp",
		"model_provider": "openai",
		"model_name": "gpt-4o",
		"output_mode": "raw",
	}
}

# -- Decision values --

test_decision_allow if {
	decision.decision == "allow" with input as {
		"tenant_id": "acme-corp",
		"model_provider": "openai",
		"model_name": "gpt-4o",
		"output_mode": "hash_only",
	}
}

test_decision_deny if {
	decision.decision == "deny" with input as {
		"tenant_id": "",
		"model_provider": "",
		"model_name": "",
		"output_mode": "",
	}
}

# -- Rule IDs --

test_rule_ids_missing_tenant if {
	"missing_tenant_id" in decision.rule_ids with input as {
		"tenant_id": "",
		"model_provider": "openai",
		"model_name": "gpt-4o",
		"output_mode": "hash_only",
	}
}

test_rule_ids_missing_model if {
	"missing_model" in decision.rule_ids with input as {
		"tenant_id": "acme-corp",
		"model_provider": "",
		"model_name": "",
		"output_mode": "hash_only",
	}
}

test_rule_ids_base_allow if {
	"base_allow" in decision.rule_ids with input as {
		"tenant_id": "acme-corp",
		"model_provider": "openai",
		"model_name": "gpt-4o",
		"output_mode": "hash_only",
	}
}
