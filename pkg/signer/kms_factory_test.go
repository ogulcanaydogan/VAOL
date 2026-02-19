package signer

import "testing"

func TestNewKMSBackendLocal(t *testing.T) {
	backend, err := NewKMSBackend(KMSConfig{
		Provider: KMSProviderLocal,
		KeyURI:   "local://test",
	})
	if err != nil {
		t.Fatalf("NewKMSBackend local: %v", err)
	}
	if backend == nil {
		t.Fatal("expected backend")
	}
}

func TestNewKMSBackendGCPRequiresToken(t *testing.T) {
	_, err := NewKMSBackend(KMSConfig{
		Provider: KMSProviderGCP,
		KeyURI:   "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
	})
	if err == nil {
		t.Fatal("expected token requirement error")
	}
}

func TestNewKMSBackendAzureRequiresToken(t *testing.T) {
	_, err := NewKMSBackend(KMSConfig{
		Provider: KMSProviderAzure,
		KeyURI:   "https://vault.vault.azure.net/keys/key/version",
	})
	if err == nil {
		t.Fatal("expected token requirement error")
	}
}
