package pqc

import (
	"bytes"
	"errors"
	"sync"
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
	if _, err := New(s.Algorithm(), s.SecretKey()[:1], s.PublicKey()); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("secret key: got %v, want ErrInvalidKeyLength", err)
	}
	if _, err := New(s.Algorithm(), s.SecretKey(), s.PublicKey()[:1]); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("public key: got %v, want ErrInvalidKeyLength", err)
	}
}

func TestGenerateRequiresAlgorithm(t *testing.T) {
	if _, err := Generate(""); !errors.Is(err, ErrAlgorithmRequired) {
		t.Fatalf("got %v, want ErrAlgorithmRequired", err)
	}
	if _, err := Generate("   "); !errors.Is(err, ErrAlgorithmRequired) {
		t.Fatalf("got %v, want ErrAlgorithmRequired", err)
	}
}

func TestGenerateUnknownAlgorithm(t *testing.T) {
	if _, err := Generate("not-a-real-algorithm"); err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}

func TestSignAfterClean(t *testing.T) {
	s, err := Generate(AlgMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	s.Clean()
	if _, err := s.Sign([]byte("x")); !errors.Is(err, ErrSignerCleaned) {
		t.Fatalf("got %v, want ErrSignerCleaned", err)
	}
}

func TestSignConcurrent(t *testing.T) {
	s, err := Generate(AlgMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Clean)

	const n = 8
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			msg := []byte{byte(i)}
			sig, err := s.Sign(msg)
			if err != nil {
				errCh <- err
				return
			}
			ok, err := Verify(s.Algorithm(), msg, sig, s.PublicKey())
			if err != nil {
				errCh <- err
				return
			}
			if !ok {
				errCh <- errors.New("signature did not verify")
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func TestSignVerifyWithContext(t *testing.T) {
	s, err := Generate(AlgMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Clean)
	if !s.Details().SigWithCtxSupport {
		t.Fatal("ML-DSA-65 should support a context string")
	}

	msg := []byte("context message")
	ctx := []byte("qday-pqc-sdk")
	sig, err := s.SignWithContext(msg, ctx)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyWithContext(s.Algorithm(), msg, sig, ctx, s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected context signature to verify")
	}

	ok, err = VerifyWithContext(s.Algorithm(), msg, sig, []byte("other"), s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected wrong context to fail verification")
	}

	v, err := NewVerifier(s.Algorithm(), s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	ok, err = v.VerifyWithContext(msg, sig, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected Verifier context check to succeed")
	}
}

func TestSignWithContextUnsupported(t *testing.T) {
	s, err := Generate(AlgFalcon512)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Clean)
	if s.Details().SigWithCtxSupport {
		t.Skip("this Falcon-512 build supports context strings")
	}
	if _, err := s.SignWithContext([]byte("x"), []byte("ctx")); !errors.Is(err, ErrContextUnsupported) {
		t.Fatalf("got %v, want ErrContextUnsupported", err)
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
	if IsAlgorithmEnabled("") {
		t.Fatal("empty algorithm should not be enabled")
	}
	if Version() == "" {
		t.Fatal("expected liboqs version")
	}

	d, err := AlgorithmDetails(AlgMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != AlgMLDSA65 || d.LengthPublicKey == 0 || d.LengthSecretKey == 0 {
		t.Fatalf("unexpected details: %+v", d)
	}
	if _, err := AlgorithmDetails(""); !errors.Is(err, ErrAlgorithmRequired) {
		t.Fatalf("got %v, want ErrAlgorithmRequired", err)
	}
}
