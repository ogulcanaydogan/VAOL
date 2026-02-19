# Tests for VAOL mandatory_citations policy

package vaol.mandatory_citations_test

import rego.v1

import data.vaol.mandatory_citations

test_allow_no_rag_context if {
	mandatory_citations.allow with input as {
		"has_rag_context": false,
		"has_citations": false,
	}
}

test_allow_rag_with_citations if {
	mandatory_citations.allow with input as {
		"has_rag_context": true,
		"has_citations": true,
	}
}

test_deny_rag_without_citations if {
	not mandatory_citations.allow with input as {
		"has_rag_context": true,
		"has_citations": false,
	}
}

test_decision_deny_missing_citations if {
	mandatory_citations.decision == "deny" with input as {
		"has_rag_context": true,
		"has_citations": false,
	}
}

test_decision_allow_with_citations if {
	mandatory_citations.decision == "allow" with input as {
		"has_rag_context": true,
		"has_citations": true,
	}
}

test_rule_id_missing_citations if {
	"rag_missing_citations" in mandatory_citations.rule_ids with input as {
		"has_rag_context": true,
		"has_citations": false,
	}
}

test_rule_id_citations_present if {
	"rag_citations_present" in mandatory_citations.rule_ids with input as {
		"has_rag_context": true,
		"has_citations": true,
	}
}

test_reason_present_when_denied if {
	mandatory_citations.reason with input as {
		"has_rag_context": true,
		"has_citations": false,
	}
}
