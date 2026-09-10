package pqc

import "github.com/open-quantum-safe/liboqs-go/oqs"

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
	return oqs.IsSigEnabled(alg)
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
