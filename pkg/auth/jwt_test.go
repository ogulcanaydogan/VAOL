package auth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyAuthorizationHS256Required(t *testing.T) {
	verifier, err := NewVerifier(Config{
		Mode:        ModeRequired,
		Issuer:      "https://issuer.example",
		Audience:    "vaol-api",
		HS256Secret: "super-secret",
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token, err := makeHS256Token(map[string]any{
		"iss":       "https://issuer.example",
		"aud":       "vaol-api",
		"sub":       "svc-app",
		"tenant_id": "acme-prod",
		"exp":       time.Now().Add(10 * time.Minute).Unix(),
	}, "super-secret")
	if err != nil {
		t.Fatalf("makeHS256Token: %v", err)
	}

	claims, err := verifier.VerifyAuthorization(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("VerifyAuthorization: %v", err)
	}
	if claims.TenantID != "acme-prod" {
		t.Fatalf("tenant mismatch: got %q", claims.TenantID)
	}
	if claims.Subject != "svc-app" {
		t.Fatalf("subject mismatch: got %q", claims.Subject)
	}
	if claims.TokenHash == "" {
		t.Fatal("expected token hash")
	}
}

func TestVerifyAuthorizationOptionalNoToken(t *testing.T) {
	verifier, err := NewVerifier(Config{
		Mode:        ModeOptional,
		HS256Secret: "secret",
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	claims, err := verifier.VerifyAuthorization(context.Background(), "")
	if err != nil {
		t.Fatalf("VerifyAuthorization: %v", err)
	}
	if claims != nil {
		t.Fatalf("expected nil claims for no token in optional mode, got %+v", claims)
	}
}

func TestVerifyAuthorizationMissingTenantFails(t *testing.T) {
	verifier, err := NewVerifier(Config{
		Mode:        ModeRequired,
		Issuer:      "https://issuer.example",
		HS256Secret: "secret",
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token, err := makeHS256Token(map[string]any{
		"iss": "https://issuer.example",
		"sub": "svc-app",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
	}, "secret")
	if err != nil {
		t.Fatalf("makeHS256Token: %v", err)
	}

	if _, err := verifier.VerifyAuthorization(context.Background(), "Bearer "+token); err == nil {
		t.Fatal("expected error for missing tenant claim")
	}
}

func TestVerifyAuthorizationExpiredTokenFails(t *testing.T) {
	verifier, err := NewVerifier(Config{
		Mode:        ModeRequired,
		HS256Secret: "secret",
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token, err := makeHS256Token(map[string]any{
		"sub":       "svc-app",
		"tenant_id": "acme",
		"exp":       time.Now().Add(-1 * time.Hour).Unix(),
	}, "secret")
	if err != nil {
		t.Fatalf("makeHS256Token: %v", err)
	}

	if _, err := verifier.VerifyAuthorization(context.Background(), "Bearer "+token); err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestVerifyAuthorizationRS256JWKS(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwksPath, []byte(makeRSAJWKS("k1", &priv.PublicKey)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	verifier, err := NewVerifier(Config{
		Mode:      ModeRequired,
		Issuer:    "https://issuer.example",
		Audience:  "vaol-api",
		JWKSFile:  jwksPath,
		ClockSkew: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token, err := makeRS256Token("k1", map[string]any{
		"iss":       "https://issuer.example",
		"aud":       []string{"vaol-api"},
		"sub":       "svc-rs256",
		"tenant_id": "acme-rs",
		"exp":       time.Now().Add(15 * time.Minute).Unix(),
	}, priv)
	if err != nil {
		t.Fatalf("makeRS256Token: %v", err)
	}

	claims, err := verifier.VerifyAuthorization(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("VerifyAuthorization: %v", err)
	}
	if claims.Subject != "svc-rs256" || claims.TenantID != "acme-rs" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func makeHS256Token(claims map[string]any, secret string) (string, error) {
	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func makeRS256Token(kid string, claims map[string]any, priv *rsa.PrivateKey) (string, error) {
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func makeRSAJWKS(kid string, pub *rsa.PublicKey) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(bigIntFromInt(pub.E).Bytes())
	return fmt.Sprintf(`{"keys":[{"kid":"%s","kty":"RSA","alg":"RS256","use":"sig","n":"%s","e":"%s"}]}`, kid, n, e)
}

func bigIntFromInt(v int) *big.Int {
	return new(big.Int).SetInt64(int64(v))
}
