# VAOL Policy: Deny Plaintext Storage
# Prevents storing raw prompts/outputs in plaintext mode.
# Organizations should use hash_only (default) or encrypted mode.

package vaol.deny_plaintext

import rego.v1

default allow := true
default decision := "allow"

allow := false if {
    input.output_mode == "plaintext"
}

decision := "deny" if {
    not allow
}

rule_ids contains "deny_plaintext_output" if {
    input.output_mode == "plaintext"
}

reason := "plaintext output storage is denied by policy; use hash_only or encrypted mode" if {
    not allow
}
