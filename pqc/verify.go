package pqc

import (
	"fmt"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// Verify reports whether signature is valid for message under publicKey.
// A cryptographic mismatch returns (false, nil).
func Verify(algName string, message, signature, publicKey []byte) (bool, error) {
	verifier := oqs.Signature{}
	defer verifier.Clean()

	if err := verifier.Init(algName, nil); err != nil {
		return false, fmt.Errorf("init verifier %q: %w", algName, err)
	}

	ok, err := verifier.Verify(message, signature, publicKey)
	if err != nil {
		return false, fmt.Errorf("verify: %w", err)
	}
	return ok, nil
}

// Verifier checks signatures against a fixed public key.
type Verifier struct {
	alg       string
	publicKey []byte
}

// NewVerifier prepares a verifier for alg and publicKey.
func NewVerifier(alg string, publicKey []byte) (*Verifier, error) {
	tmp := oqs.Signature{}
	defer tmp.Clean()
	if err := tmp.Init(alg, nil); err != nil {
		return nil, fmt.Errorf("init verifier %q: %w", alg, err)
	}
	want := tmp.Details().LengthPublicKey
	if len(publicKey) != want {
		return nil, fmt.Errorf("public key length %d, want %d", len(publicKey), want)
	}
	return &Verifier{alg: alg, publicKey: append([]byte(nil), publicKey...)}, nil
}

// Algorithm returns the liboqs signature name.
func (v *Verifier) Algorithm() string { return v.alg }

// PublicKey returns a copy of the public key.
func (v *Verifier) PublicKey() []byte {
	out := make([]byte, len(v.publicKey))
	copy(out, v.publicKey)
	return out
}

// Verify reports whether signature is valid for message.
func (v *Verifier) Verify(message, signature []byte) (bool, error) {
	return Verify(v.alg, message, signature, v.publicKey)
}
