package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSignTwiceStillVerifies(t *testing.T) {
	signer, err := GenerateSigner("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	for i, msg := range [][]byte{[]byte("first"), []byte("second")} {
		sig, err := signer.Sign(msg)
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		ok, err := Verify(signer.Algorithm(), msg, sig, signer.PublicKey())
		if err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
		if !ok {
			t.Fatalf("expected signature %d to verify", i)
		}
	}
}

func TestSignVerify(t *testing.T) {
	const alg = "ML-DSA-65"
	msg := []byte("pqc sign/verify test")

	signer, err := GenerateSigner(alg)
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	if len(signer.PublicKey()) == 0 {
		t.Fatal("expected non-empty public key")
	}

	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}

	ok, err := Verify(alg, msg, sig, signer.PublicKey())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected valid signature")
	}

	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0x01
	ok, err = Verify(alg, tampered, sig, signer.PublicKey())
	if err != nil {
		t.Fatalf("Verify tampered: %v", err)
	}
	if ok {
		t.Fatal("expected tampered message to fail verification")
	}
}

func TestLoadOrGenerateSignerPersistsKeys(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Algorithm:     "ML-DSA-65",
		SecretKeyFile: filepath.Join(dir, "secret.key"),
		PublicKeyFile: filepath.Join(dir, "public.key"),
	}

	first, err := LoadOrGenerateSigner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("persist")
	sig, err := first.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	second, err := LoadOrGenerateSigner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PublicKey(), second.PublicKey()) {
		t.Fatal("reloaded public key mismatch")
	}
	ok, err := Verify(cfg.Algorithm, msg, sig, second.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature from first signer should verify with reloaded key")
	}
}

func TestLoadOrGenerateSignerIncompleteFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Algorithm:     "ML-DSA-65",
		SecretKeyFile: filepath.Join(dir, "secret.key"),
		PublicKeyFile: filepath.Join(dir, "public.key"),
	}
	if err := os.WriteFile(cfg.SecretKeyFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateSigner(cfg); err == nil {
		t.Fatal("expected error for incomplete key files")
	}
}
