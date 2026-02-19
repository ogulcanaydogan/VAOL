# Tests for VAOL model_allowlist policy

package vaol.model_allowlist_test

import rego.v1

import data.vaol.model_allowlist

test_allow_gpt4o if {
	model_allowlist.allow with input as {"model_name": "gpt-4o"}
}

test_allow_gpt4o_mini if {
	model_allowlist.allow with input as {"model_name": "gpt-4o-mini"}
}

test_allow_gpt4_turbo if {
	model_allowlist.allow with input as {"model_name": "gpt-4-turbo"}
}

test_allow_claude_sonnet if {
	model_allowlist.allow with input as {"model_name": "claude-sonnet-4-5-20250929"}
}

test_allow_claude_haiku if {
	model_allowlist.allow with input as {"model_name": "claude-haiku-4-5-20251001"}
}

test_allow_claude_opus if {
	model_allowlist.allow with input as {"model_name": "claude-opus-4-6"}
}

test_deny_unknown_model if {
	not model_allowlist.allow with input as {"model_name": "gpt-3.5-turbo"}
}

test_deny_empty_model if {
	not model_allowlist.allow with input as {"model_name": ""}
}

test_deny_llama if {
	not model_allowlist.allow with input as {"model_name": "llama-3-70b"}
}

test_decision_allow if {
	model_allowlist.decision == "allow" with input as {"model_name": "gpt-4o"}
}

test_decision_deny if {
	model_allowlist.decision == "deny" with input as {"model_name": "gpt-3.5-turbo"}
}

test_rule_id_not_in_allowlist if {
	"model_not_in_allowlist" in model_allowlist.rule_ids with input as {"model_name": "gpt-3.5-turbo"}
}

test_rule_id_model_allowed if {
	"model_allowed" in model_allowlist.rule_ids with input as {"model_name": "gpt-4o"}
}

test_reason_present_when_denied if {
	model_allowlist.reason with input as {"model_name": "gpt-3.5-turbo"}
}
