package pqc

import (
	"bytes"
	"fmt"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// Verify reports whether signature is valid for message under publicKey.
// A cryptographic mismatch returns (false, nil).
func Verify(algName string, message, signature, publicKey []byte) (bool, error) {
	return verify(algName, message, signature, nil, publicKey)
}

// VerifyWithContext reports whether signature is valid for message under
// publicKey with the same context string used at sign time.
func VerifyWithContext(algName string, message, signature, context, publicKey []byte) (bool, error) {
	return verify(algName, message, signature, context, publicKey)
}

func verify(algName string, message, signature, context, publicKey []byte) (bool, error) {
	algName, err := normalizeAlg(algName)
	if err != nil {
		return false, err
	}

	verifier := oqs.Signature{}
	defer verifier.Clean()

	if err := verifier.Init(algName, nil); err != nil {
		return false, fmt.Errorf("init verifier %q: %w", algName, err)
	}
	if len(context) > 0 && !verifier.Details().SigWithCtxSupport {
		return false, fmt.Errorf("%w: %s", ErrContextUnsupported, algName)
	}

	var ok bool
	if len(context) == 0 {
		ok, err = verifier.Verify(message, signature, publicKey)
	} else {
		ok, err = verifier.VerifyWithCtxStr(message, signature, context, publicKey)
	}
	if err != nil {
		return false, fmt.Errorf("verify: %w", err)
	}
	return ok, nil
}

// Verifier checks signatures against a fixed public key.
type Verifier struct {
	alg       string
	publicKey []byte
	details   Details
}

// NewVerifier prepares a verifier for alg and publicKey.
func NewVerifier(alg string, publicKey []byte) (*Verifier, error) {
	alg, err := normalizeAlg(alg)
	if err != nil {
		return nil, err
	}
	tmp := oqs.Signature{}
	defer tmp.Clean()
	if err := tmp.Init(alg, nil); err != nil {
		return nil, fmt.Errorf("init verifier %q: %w", alg, err)
	}
	details := detailsFrom(tmp.Details())
	if len(publicKey) != details.LengthPublicKey {
		return nil, fmt.Errorf("%w: public key length %d, want %d", ErrInvalidKeyLength, len(publicKey), details.LengthPublicKey)
	}
	return &Verifier{
		alg:       alg,
		publicKey: bytes.Clone(publicKey),
		details:   details,
	}, nil
}

// Algorithm returns the liboqs signature name.
func (v *Verifier) Algorithm() string {
	if v == nil {
		return ""
	}
	return v.alg
}

// PublicKey returns a copy of the public key.
func (v *Verifier) PublicKey() []byte {
	if v == nil {
		return nil
	}
	return bytes.Clone(v.publicKey)
}

// Details returns algorithm parameters for this public key.
func (v *Verifier) Details() Details {
	if v == nil {
		return Details{}
	}
	return v.details
}

// Verify reports whether signature is valid for message.
func (v *Verifier) Verify(message, signature []byte) (bool, error) {
	if v == nil {
		return false, ErrAlgorithmRequired
	}
	return Verify(v.alg, message, signature, v.publicKey)
}

// VerifyWithContext reports whether signature is valid for message using context.
func (v *Verifier) VerifyWithContext(message, signature, context []byte) (bool, error) {
	if v == nil {
		return false, ErrAlgorithmRequired
	}
	return VerifyWithContext(v.alg, message, signature, context, v.publicKey)
}
