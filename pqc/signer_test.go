package pqc

import (
	"bytes"
	"testing"
)

func TestSignTwiceStillVerifies(t *testing.T) {
	s, err := Generate(AlgMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Clean)
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
	testSignVerifyAlg(t, AlgMLDSA65)
}

func TestSignVerifyFalcon512(t *testing.T) {
	testSignVerifyAlg(t, AlgFalcon512)
}

func testSignVerifyAlg(t *testing.T, alg string) {
	t.Helper()
	msg := []byte("pqc sign/verify test")

	s, err := Generate(alg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(s.Clean)
	if len(s.PublicKey()) == 0 {
		t.Fatal("expected non-empty public key")
	}
	if s.Details().Name != alg {
		t.Fatalf("details name = %q, want %q", s.Details().Name, alg)
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

	v, err := NewVerifier(alg, s.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ok, err = v.Verify(msg, sig)
	if err != nil {
		t.Fatalf("Verifier.Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected verifier to accept signature")
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

func TestNewRoundTrip(t *testing.T) {
	first, err := Generate(AlgMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.Clean)

	second, err := New(first.Algorithm(), first.SecretKey(), first.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(second.Clean)

	msg := []byte("round-trip")
	sig, err := first.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PublicKey(), second.PublicKey()) {
		t.Fatal("reconstructed public key mismatch")
	}
	ok, err := Verify(second.Algorithm(), msg, sig, second.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature should verify with reconstructed signer")
	}
}

func TestNewRejectsWrongKeyLength(t *testing.T) {
	s, err := Generate(AlgMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Clean)
	if _, err := New(s.Algorithm(), s.SecretKey()[:1], s.PublicKey()); err == nil {
		t.Fatal("expected error for truncated secret key")
	}
	if _, err := New(s.Algorithm(), s.SecretKey(), s.PublicKey()[:1]); err == nil {
		t.Fatal("expected error for truncated public key")
	}
}

func TestEnabledAlgorithms(t *testing.T) {
	algs := EnabledAlgorithms()
	if len(algs) == 0 {
		t.Fatal("expected enabled algorithms")
	}
	if !IsAlgorithmEnabled(AlgMLDSA65) {
		t.Fatal("ML-DSA-65 should be enabled")
	}
	if Version() == "" {
		t.Fatal("expected liboqs version")
	}
}
