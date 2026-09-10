package pqc

import (
	"bytes"
	"fmt"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// Signer holds a post-quantum key pair and can create detached signatures.
// Sign is safe for concurrent use.
type Signer struct {
	alg       string
	secretKey []byte
	publicKey []byte
	details   Details
}

// Generate creates a new key pair for alg.
func Generate(alg string) (*Signer, error) {
	alg, err := normalizeAlg(alg)
	if err != nil {
		return nil, err
	}

	sig := oqs.Signature{}
	defer sig.Clean()

	if err := sig.Init(alg, nil); err != nil {
		return nil, fmt.Errorf("init signer %q: %w", alg, err)
	}

	pubKey, err := sig.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}

	return &Signer{
		alg:       alg,
		secretKey: bytes.Clone(sig.ExportSecretKey()),
		publicKey: pubKey,
		details:   detailsFrom(sig.Details()),
	}, nil
}

// New reconstructs a Signer from an existing key pair.
func New(alg string, secretKey, publicKey []byte) (*Signer, error) {
	alg, err := normalizeAlg(alg)
	if err != nil {
		return nil, err
	}

	sig := oqs.Signature{}
	defer sig.Clean()

	if err := sig.Init(alg, secretKey); err != nil {
		return nil, fmt.Errorf("init signer %q: %w", alg, err)
	}

	details := sig.Details()
	if len(secretKey) != details.LengthSecretKey {
		return nil, fmt.Errorf("%w: secret key length %d, want %d", ErrInvalidKeyLength, len(secretKey), details.LengthSecretKey)
	}
	if len(publicKey) != details.LengthPublicKey {
		return nil, fmt.Errorf("%w: public key length %d, want %d", ErrInvalidKeyLength, len(publicKey), details.LengthPublicKey)
	}

	return &Signer{
		alg:       alg,
		secretKey: bytes.Clone(secretKey),
		publicKey: bytes.Clone(publicKey),
		details:   detailsFrom(details),
	}, nil
}

// Algorithm returns the liboqs signature name, e.g. ML-DSA-65.
func (s *Signer) Algorithm() string {
	if s == nil {
		return ""
	}
	return s.alg
}

// PublicKey returns a copy of the public key.
func (s *Signer) PublicKey() []byte {
	if s == nil {
		return nil
	}
	return bytes.Clone(s.publicKey)
}

// SecretKey returns a copy of the secret key. Treat it as sensitive material.
func (s *Signer) SecretKey() []byte {
	if s == nil {
		return nil
	}
	return bytes.Clone(s.secretKey)
}

// Details returns algorithm parameters for this key pair.
func (s *Signer) Details() Details {
	if s == nil {
		return Details{}
	}
	return s.details
}

// Sign creates a detached signature over message.
func (s *Signer) Sign(message []byte) ([]byte, error) {
	return s.sign(message, nil)
}

// SignWithContext creates a detached signature over message with a context
// string (FIPS 204). context may be empty. Algorithms that do not support a
// context string reject a non-empty context.
func (s *Signer) SignWithContext(message, context []byte) ([]byte, error) {
	return s.sign(message, context)
}

func (s *Signer) sign(message, context []byte) ([]byte, error) {
	if s == nil || len(s.secretKey) == 0 {
		return nil, ErrSignerCleaned
	}
	if len(context) > 0 && !s.details.SigWithCtxSupport {
		return nil, fmt.Errorf("%w: %s", ErrContextUnsupported, s.alg)
	}

	sig := oqs.Signature{}
	defer sig.Clean()

	// liboqs-go Clean() zeroes the key slice it was initialized with.
	sk := bytes.Clone(s.secretKey)
	if err := sig.Init(s.alg, sk); err != nil {
		return nil, fmt.Errorf("init signer %q: %w", s.alg, err)
	}

	var (
		signature []byte
		err       error
	)
	if len(context) == 0 {
		signature, err = sig.Sign(message)
	} else {
		signature, err = sig.SignWithCtxStr(message, context)
	}
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return signature, nil
}

// Clean zeroes the in-memory secret key. The Signer must not be used after
// Clean except to read Algorithm, PublicKey, or Details.
func (s *Signer) Clean() {
	if s == nil || len(s.secretKey) == 0 {
		return
	}
	oqs.MemCleanse(s.secretKey)
	s.secretKey = nil
}
