package verifier

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Report generates a human-readable verification report.
type Report struct {
	Title     string       `json:"title"`
	Generated time.Time    `json:"generated"`
	Bundle    BundleResult `json:"bundle"`
}

// NewReport creates a verification report from a bundle result.
func NewReport(title string, bundle BundleResult) *Report {
	return &Report{
		Title:     title,
		Generated: time.Now().UTC(),
		Bundle:    bundle,
	}
}

// ToJSON serializes the report as indented JSON.
func (r *Report) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ToMarkdown generates a Markdown-formatted verification report.
func (r *Report) ToMarkdown() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# %s\n\n", r.Title))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", r.Generated.Format(time.RFC3339)))

	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| Total records | %d |\n", r.Bundle.TotalRecords))
	b.WriteString(fmt.Sprintf("| Valid records | %d |\n", r.Bundle.ValidRecords))
	b.WriteString(fmt.Sprintf("| Invalid records | %d |\n", r.Bundle.InvalidRecords))
	b.WriteString(fmt.Sprintf("| Hash chain | %s |\n", passFailIcon(r.Bundle.ChainIntact)))
	b.WriteString(fmt.Sprintf("| Merkle proofs | %s |\n", passFailIcon(r.Bundle.MerkleValid)))
	b.WriteString(fmt.Sprintf("| Signatures | %s |\n", passFailIcon(r.Bundle.SignaturesValid)))
	b.WriteString(fmt.Sprintf("| Schema | %s |\n", passFailIcon(r.Bundle.SchemaValid)))
	b.WriteString("\n")

	if r.Bundle.InvalidRecords > 0 {
		b.WriteString("## Failures\n\n")
		for _, res := range r.Bundle.Results {
			if !res.Valid {
				b.WriteString(fmt.Sprintf("### Record %s\n\n", res.RequestID))
				for _, check := range res.Checks {
					if !check.Passed {
						b.WriteString(fmt.Sprintf("- **%s**: %s\n", check.Name, check.Error))
					}
				}
				b.WriteString("\n")
			}
		}
	}

	b.WriteString(fmt.Sprintf("## Conclusion\n\n%s\n", r.Bundle.Summary))

	return b.String()
}

func passFailIcon(passed bool) string {
	if passed {
		return "PASS"
	}
	return "FAIL"
}
