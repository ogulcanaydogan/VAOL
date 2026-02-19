// Package auth provides JWT/OIDC authentication and tenant claim binding for VAOL APIs.
package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	vaolcrypto "github.com/ogulcanaydogan/vaol/pkg/crypto"
)

// Mode controls API authentication behavior.
type Mode string

const (
	ModeDisabled Mode = "disabled"
	ModeOptional Mode = "optional"
	ModeRequired Mode = "required"
)

// ParseMode validates and normalizes the configured auth mode.
func ParseMode(v string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", string(ModeDisabled):
		return ModeDisabled, nil
	case string(ModeOptional):
		return ModeOptional, nil
	case string(ModeRequired):
		return ModeRequired, nil
	default:
		return "", fmt.Errorf("invalid auth mode %q (expected disabled|optional|required)", v)
	}
}

// Config configures JWT verification.
type Config struct {
	Mode         Mode          `json:"mode"`
	Issuer       string        `json:"issuer,omitempty"`
	Audience     string        `json:"audience,omitempty"`
	TenantClaim  string        `json:"tenant_claim,omitempty"`
	SubjectClaim string        `json:"subject_claim,omitempty"`
	JWKSFile     string        `json:"jwks_file,omitempty"`
	JWKSURL      string        `json:"jwks_url,omitempty"`
	HS256Secret  string        `json:"hs256_secret,omitempty"`
	ClockSkew    time.Duration `json:"clock_skew,omitempty"`
	HTTPTimeout  time.Duration `json:"http_timeout,omitempty"`
}

// Claims contains normalized identity extracted from a verified token.
type Claims struct {
	Issuer    string         `json:"issuer"`
	Subject   string         `json:"subject"`
	TenantID  string         `json:"tenant_id"`
	Audience  []string       `json:"audience,omitempty"`
	ExpiresAt time.Time      `json:"expires_at"`
	TokenHash string         `json:"token_hash"`
	RawClaims map[string]any `json:"raw_claims,omitempty"`
}

// Verifier validates JWTs and extracts tenant/subject claims.
type Verifier struct {
	cfg        Config
	httpClient *http.Client
	pubKeys    map[string]any
	hsSecret   []byte
}

// NewVerifier creates an auth verifier from config.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModeDisabled
	}
	if cfg.TenantClaim == "" {
		cfg.TenantClaim = "tenant_id"
	}
	if cfg.SubjectClaim == "" {
		cfg.SubjectClaim = "sub"
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 30 * time.Second
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}

	v := &Verifier{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: cfg.HTTPTimeout},
		pubKeys:    map[string]any{},
	}

	if cfg.Mode == ModeDisabled {
		return v, nil
	}

	if cfg.HS256Secret != "" {
		v.hsSecret = []byte(cfg.HS256Secret)
	}
	if cfg.JWKSFile != "" {
		if err := v.loadJWKSFromFile(cfg.JWKSFile); err != nil {
			return nil, err
		}
	}
	if cfg.JWKSURL != "" {
		if err := v.loadJWKSFromURL(context.Background(), cfg.JWKSURL); err != nil {
			return nil, err
		}
	}

	if len(v.pubKeys) == 0 && len(v.hsSecret) == 0 {
		return nil, fmt.Errorf("auth enabled but no JWT verification material configured (set jwks-file/jwks-url or hs256 secret)")
	}

	return v, nil
}

// VerifyAuthorization verifies a Bearer token and returns normalized claims.
// When auth mode is optional and no token is present, returns (nil, nil).
func (v *Verifier) VerifyAuthorization(ctx context.Context, authorization string) (*Claims, error) {
	switch v.cfg.Mode {
	case ModeDisabled:
		return nil, nil
	case ModeOptional:
		if strings.TrimSpace(authorization) == "" {
			return nil, nil
		}
	}

	token, err := parseBearerToken(authorization)
	if err != nil {
		return nil, err
	}

	header, payloadBytes, signingInput, sigBytes, err := parseJWT(token)
	if err != nil {
		return nil, err
	}

	key, err := v.keyFor(header)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(header.Alg, key, signingInput, sigBytes); err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := json.Unmarshal(payloadBytes, &raw); err != nil {
		return nil, fmt.Errorf("invalid JWT claims: %w", err)
	}

	now := time.Now().UTC()
	if err := v.validateTemporalClaims(raw, now); err != nil {
		return nil, err
	}
	if err := v.validateIssuerAndAudience(raw); err != nil {
		return nil, err
	}

	tenantID, _ := rawStringClaim(raw, v.cfg.TenantClaim)
	if v.cfg.Mode == ModeRequired && tenantID == "" {
		return nil, fmt.Errorf("token missing required tenant claim %q", v.cfg.TenantClaim)
	}

	subject, _ := rawStringClaim(raw, v.cfg.SubjectClaim)
	if v.cfg.Mode == ModeRequired && subject == "" {
		return nil, fmt.Errorf("token missing required subject claim %q", v.cfg.SubjectClaim)
	}

	issuer, _ := rawStringClaim(raw, "iss")
	expiresAt, _ := parseNumericDate(raw["exp"])
	audience := parseAudience(raw["aud"])

	return &Claims{
		Issuer:    issuer,
		Subject:   subject,
		TenantID:  tenantID,
		Audience:  audience,
		ExpiresAt: expiresAt,
		TokenHash: vaolcrypto.SHA256Prefixed([]byte(token)),
		RawClaims: raw,
	}, nil
}

// InjectTrustedHeaders clones a request and injects trusted identity headers.
// User-supplied spoofable auth headers are replaced.
func InjectTrustedHeaders(r *http.Request, claims *Claims) *http.Request {
	if claims == nil {
		return r
	}
	rr := r.Clone(r.Context())
	rr.Header = r.Header.Clone()

	// Replace caller-supplied identity hints with verified claims.
	rr.Header.Del("Authorization")
	rr.Header.Set("X-Auth-Source", "jwt")
	rr.Header.Set("X-Auth-Token-Hash", claims.TokenHash)
	if claims.Issuer != "" {
		rr.Header.Set("X-Auth-Issuer", claims.Issuer)
	}
	if claims.Subject != "" {
		rr.Header.Set("X-Auth-Subject", claims.Subject)
	}
	if claims.TenantID != "" {
		rr.Header.Set("X-VAOL-Tenant-ID", claims.TenantID)
	}
	return rr
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

func parseBearerToken(authorization string) (string, error) {
	authorization = strings.TrimSpace(authorization)
	if authorization == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("invalid Authorization scheme (expected Bearer token)")
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", fmt.Errorf("empty bearer token")
	}
	return token, nil
}

func parseJWT(token string) (*jwtHeader, []byte, string, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, "", nil, fmt.Errorf("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("decoding JWT header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, "", nil, fmt.Errorf("invalid JWT header: %w", err)
	}
	if header.Alg == "" {
		return nil, nil, "", nil, fmt.Errorf("JWT header missing alg")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("decoding JWT signature: %w", err)
	}

	return &header, payloadBytes, parts[0] + "." + parts[1], sigBytes, nil
}

func (v *Verifier) keyFor(header *jwtHeader) (any, error) {
	switch header.Alg {
	case "HS256":
		if len(v.hsSecret) == 0 {
			return nil, fmt.Errorf("HS256 token received but no shared secret configured")
		}
		return v.hsSecret, nil
	case "RS256", "ES256":
		// continue below
	default:
		return nil, fmt.Errorf("unsupported JWT alg %q", header.Alg)
	}

	if header.Kid != "" {
		if k, ok := v.pubKeys[header.Kid]; ok {
			return k, nil
		}
		return nil, fmt.Errorf("no verification key for kid %q", header.Kid)
	}
	if len(v.pubKeys) == 1 {
		for _, k := range v.pubKeys {
			return k, nil
		}
	}
	return nil, fmt.Errorf("JWT missing kid and verifier has multiple keys")
}

func verifySignature(alg string, key any, signingInput string, sig []byte) error {
	digest := sha256.Sum256([]byte(signingInput))

	switch alg {
	case "HS256":
		secret, ok := key.([]byte)
		if !ok {
			return fmt.Errorf("invalid HS256 key type")
		}
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write([]byte(signingInput))
		expected := mac.Sum(nil)
		if !hmac.Equal(expected, sig) {
			return fmt.Errorf("JWT HMAC verification failed")
		}
		return nil
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid RS256 key type")
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("JWT RSA verification failed: %w", err)
		}
		return nil
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid ES256 key type")
		}
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return fmt.Errorf("JWT ECDSA verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported JWT alg %q", alg)
	}
}

func (v *Verifier) validateIssuerAndAudience(raw map[string]any) error {
	if v.cfg.Issuer != "" {
		iss, _ := rawStringClaim(raw, "iss")
		if iss != v.cfg.Issuer {
			return fmt.Errorf("issuer mismatch: got %q want %q", iss, v.cfg.Issuer)
		}
	}
	if v.cfg.Audience != "" {
		aud := parseAudience(raw["aud"])
		found := false
		for _, a := range aud {
			if a == v.cfg.Audience {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("audience mismatch: missing %q", v.cfg.Audience)
		}
	}
	return nil
}

func (v *Verifier) validateTemporalClaims(raw map[string]any, now time.Time) error {
	skew := v.cfg.ClockSkew

	exp, hasExp := parseNumericDate(raw["exp"])
	if v.cfg.Mode == ModeRequired && !hasExp {
		return fmt.Errorf("token missing exp claim")
	}
	if hasExp && now.After(exp.Add(skew)) {
		return fmt.Errorf("token expired at %s", exp.UTC().Format(time.RFC3339))
	}

	if nbf, ok := parseNumericDate(raw["nbf"]); ok && now.Add(skew).Before(nbf) {
		return fmt.Errorf("token not valid before %s", nbf.UTC().Format(time.RFC3339))
	}
	if iat, ok := parseNumericDate(raw["iat"]); ok && iat.After(now.Add(skew)) {
		return fmt.Errorf("token issued in the future at %s", iat.UTC().Format(time.RFC3339))
	}

	return nil
}

func rawStringClaim(raw map[string]any, key string) (string, bool) {
	v, ok := raw[key]
	if !ok || v == nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t), true
	default:
		return fmt.Sprintf("%v", t), true
	}
}

func parseAudience(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func parseNumericDate(v any) (time.Time, bool) {
	switch t := v.(type) {
	case float64:
		return time.Unix(int64(t), 0).UTC(), true
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(n, 0).UTC(), true
	case int64:
		return time.Unix(t, 0).UTC(), true
	case int:
		return time.Unix(int64(t), 0).UTC(), true
	case string:
		if t == "" {
			return time.Time{}, false
		}
		// Accept numeric unix time as string.
		var num json.Number = json.Number(t)
		n, err := num.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(n, 0).UTC(), true
	default:
		return time.Time{}, false
	}
}

func (v *Verifier) loadJWKSFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading JWKS file %q: %w", path, err)
	}
	return v.parseJWKS(data)
}

func (v *Verifier) loadJWKSFromURL(ctx context.Context, u string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("creating JWKS request: %w", err)
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching JWKS URL %q: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	var body struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decoding JWKS response: %w", err)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encoding JWKS response: %w", err)
	}
	return v.parseJWKS(raw)
}

func (v *Verifier) parseJWKS(data []byte) error {
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return fmt.Errorf("parsing JWKS: %w", err)
	}
	if len(set.Keys) == 0 {
		return fmt.Errorf("JWKS contains no keys")
	}

	for i, k := range set.Keys {
		kid := strings.TrimSpace(k.Kid)
		if kid == "" {
			kid = fmt.Sprintf("jwks-%d", i)
		}
		switch k.Kty {
		case "RSA":
			pub, err := parseRSAJWK(k.N, k.E)
			if err != nil {
				return fmt.Errorf("parsing RSA key %q: %w", kid, err)
			}
			v.pubKeys[kid] = pub
		case "EC":
			pub, err := parseECJWK(k.Crv, k.X, k.Y)
			if err != nil {
				return fmt.Errorf("parsing EC key %q: %w", kid, err)
			}
			v.pubKeys[kid] = pub
		default:
			return fmt.Errorf("unsupported JWK kty %q for kid %q", k.Kty, kid)
		}
	}
	return nil
}

func parseRSAJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decoding n: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decoding e: %w", err)
	}
	n := new(big.Int).SetBytes(nb)
	e := 0
	for _, b := range eb {
		e = (e << 8) | int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func parseECJWK(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	if crv != "P-256" {
		return nil, fmt.Errorf("unsupported EC curve %q (expected P-256)", crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("decoding x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("decoding y: %w", err)
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}
