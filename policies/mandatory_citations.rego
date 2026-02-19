# VAOL Policy: Mandatory Citations for RAG
# When RAG context is present, requires that citations are included.
# This ensures that RAG-augmented outputs can be traced back to source documents.

package vaol.mandatory_citations

import rego.v1

default allow := true
default decision := "allow"

# Deny if RAG was used but no citations are present
allow := false if {
    input.has_rag_context == true
    input.has_citations == false
}

decision := "deny" if {
    not allow
}

rule_ids contains "rag_missing_citations" if {
    input.has_rag_context == true
    input.has_citations == false
}

rule_ids contains "rag_citations_present" if {
    input.has_rag_context == true
    input.has_citations == true
}

reason := "RAG-augmented outputs must include citation hashes for traceability" if {
    not allow
}
