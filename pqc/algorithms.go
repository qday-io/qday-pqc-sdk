package pqc

import (
	"fmt"
	"strings"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// Recommended ML-DSA (FIPS 204) algorithm names, matching liboqs.
const (
	AlgMLDSA44 = "ML-DSA-44"
	AlgMLDSA65 = "ML-DSA-65"
	AlgMLDSA87 = "ML-DSA-87"

	AlgFalcon512  = "Falcon-512"
	AlgFalcon1024 = "Falcon-1024"

	DefaultAlgorithm = AlgMLDSA65
)

// Version returns the linked liboqs version string.
func Version() string {
	return oqs.LiboqsVersion()
}

// EnabledAlgorithms returns a copy of signature algorithms enabled in this
// liboqs build. Names are case-sensitive.
func EnabledAlgorithms() []string {
	src := oqs.EnabledSigs()
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// IsAlgorithmEnabled reports whether alg is enabled in this liboqs build.
func IsAlgorithmEnabled(alg string) bool {
	alg = strings.TrimSpace(alg)
	if alg == "" {
		return false
	}
	return oqs.IsSigEnabled(alg)
}

func normalizeAlg(alg string) (string, error) {
	alg = strings.TrimSpace(alg)
	if alg == "" {
		return "", ErrAlgorithmRequired
	}
	return alg, nil
}

// AlgorithmDetails returns parameters for alg without creating a key pair.
func AlgorithmDetails(alg string) (Details, error) {
	alg, err := normalizeAlg(alg)
	if err != nil {
		return Details{}, err
	}
	sig := oqs.Signature{}
	defer sig.Clean()
	if err := sig.Init(alg, nil); err != nil {
		return Details{}, fmt.Errorf("init algorithm %q: %w", alg, err)
	}
	return detailsFrom(sig.Details()), nil
}

// Details describes a signature algorithm (liboqs-go field names).
type Details struct {
	Name               string
	Version            string
	ClaimedNISTLevel   int
	IsEUFCMA           bool
	SigWithCtxSupport  bool
	LengthPublicKey    int
	LengthSecretKey    int
	MaxLengthSignature int
}

func (d Details) String() string {
	return fmt.Sprintf(
		"Name: %s\nVersion: %s\nClaimed NIST level: %d\nIs EUF_CMA: %v\nContext string: %v\nLength public key (bytes): %d\nLength secret key (bytes): %d\nMax length signature (bytes): %d",
		d.Name,
		d.Version,
		d.ClaimedNISTLevel,
		d.IsEUFCMA,
		d.SigWithCtxSupport,
		d.LengthPublicKey,
		d.LengthSecretKey,
		d.MaxLengthSignature,
	)
}

func detailsFrom(d oqs.SignatureDetails) Details {
	return Details{
		Name:               d.Name,
		Version:            d.Version,
		ClaimedNISTLevel:   d.ClaimedNISTLevel,
		IsEUFCMA:           d.IsEUFCMA,
		SigWithCtxSupport:  d.SigWithCtxSupport,
		LengthPublicKey:    d.LengthPublicKey,
		LengthSecretKey:    d.LengthSecretKey,
		MaxLengthSignature: d.MaxLengthSignature,
	}
}
