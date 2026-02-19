# Tests for VAOL deny_plaintext policy

package vaol.deny_plaintext_test

import rego.v1

import data.vaol.deny_plaintext

test_allow_hash_only if {
	deny_plaintext.allow with input as {"output_mode": "hash_only"}
}

test_allow_encrypted if {
	deny_plaintext.allow with input as {"output_mode": "encrypted"}
}

test_deny_plaintext if {
	not deny_plaintext.allow with input as {"output_mode": "plaintext"}
}

test_decision_deny_plaintext if {
	deny_plaintext.decision == "deny" with input as {"output_mode": "plaintext"}
}

test_decision_allow_hash_only if {
	deny_plaintext.decision == "allow" with input as {"output_mode": "hash_only"}
}

test_rule_id_deny_plaintext if {
	"deny_plaintext_output" in deny_plaintext.rule_ids with input as {"output_mode": "plaintext"}
}

test_no_rule_id_for_hash_only if {
	count(deny_plaintext.rule_ids) == 0 with input as {"output_mode": "hash_only"}
}

test_reason_present_when_denied if {
	deny_plaintext.reason with input as {"output_mode": "plaintext"}
}
