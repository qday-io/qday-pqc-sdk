package signer

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSignTwiceStillVerifies(t *testing.T) {
	s, err := Generate("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	for i, msg := range [][]byte{[]byte("first"), []byte("second")} {
		sig, err := s.Sign(msg)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		ok, err := Verify(s.Algorithm(), msg, sig, s.PublicKey())
		if err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
		if !ok {
			t.Fatalf("expected signature %d to verify", i)
		}
	}
}

func TestSignVerify(t *testing.T) {
	testSignVerifyAlg(t, "ML-DSA-65")
}

func TestSignVerifyFalcon512(t *testing.T) {
	testSignVerifyAlg(t, "Falcon-512")
}

func testSignVerifyAlg(t *testing.T, alg string) {
	t.Helper()
	msg := []byte("pqc sign/verify test")

	s, err := Generate(alg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(s.PublicKey()) == 0 {
		t.Fatal("expected non-empty public key")
	}

	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}

	ok, err := Verify(alg, msg, sig, s.PublicKey())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected valid signature")
	}

	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0x01
	ok, err = Verify(alg, tampered, sig, s.PublicKey())
	if err != nil {
		t.Fatalf("Verify tampered: %v", err)
	}
	if ok {
		t.Fatal("expected tampered message to fail verification")
	}
}

func TestLoadOrGeneratePersistsKeys(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.key")
	pub := filepath.Join(dir, "public.key")

	first, err := LoadOrGenerate("ML-DSA-65", secret, pub)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("persist")
	sig, err := first.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	second, err := LoadOrGenerate("ML-DSA-65", secret, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PublicKey(), second.PublicKey()) {
		t.Fatal("reloaded public key mismatch")
	}
	ok, err := Verify("ML-DSA-65", msg, sig, second.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature from first signer should verify with reloaded key")
	}
}

func TestLoadOrGenerateIncompleteFiles(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.key")
	pub := filepath.Join(dir, "public.key")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerate("ML-DSA-65", secret, pub); err == nil {
		t.Fatal("expected error for incomplete key files")
	}
}
