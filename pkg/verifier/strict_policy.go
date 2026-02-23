package verifier

import "time"

// StrictPolicy configures additional strict-profile verification behavior.
//
// All checks remain opt-in through verification profile selection. A policy is
// applied only when profile=strict (or profile=fips, which builds on strict).
type StrictPolicy struct {
	OnlineRekor  bool
	RekorURL     string
	RekorTimeout time.Duration

	RequireAuthIssuer bool
	RequireAuthSource bool
}

// DefaultStrictPolicy returns verifier strict-profile defaults.
func DefaultStrictPolicy() StrictPolicy {
	return StrictPolicy{
		OnlineRekor:       false,
		RekorURL:          "",
		RekorTimeout:      10 * time.Second,
		RequireAuthIssuer: true,
		RequireAuthSource: true,
	}
}

func normalizeStrictPolicy(p StrictPolicy) StrictPolicy {
	if p == (StrictPolicy{}) {
		return DefaultStrictPolicy()
	}

	if p.RekorTimeout <= 0 {
		p.RekorTimeout = 10 * time.Second
	}

	// Preserve secure defaults when callers only set OnlineRekor/RekorURL.
	if !p.RequireAuthIssuer && !p.RequireAuthSource {
		p.RequireAuthIssuer = true
		p.RequireAuthSource = true
	}

	return p
}

// SetStrictPolicy updates strict-profile verification policy.
func (v *Verifier) SetStrictPolicy(p StrictPolicy) {
	v.strictPolicy = normalizeStrictPolicy(p)
	if v.rekorClient == nil {
		v.rekorClient = NewHTTPRekorClient(nil)
	}
}
