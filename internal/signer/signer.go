package signer

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// Signer holds a persistent post-quantum key pair used by the API.
type Signer struct {
	alg       string
	secretKey []byte
	publicKey []byte
	details   oqs.SignatureDetails
}

func Generate(alg string) (*Signer, error) {
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
		details:   sig.Details(),
	}, nil
}

func New(alg string, secretKey, publicKey []byte) (*Signer, error) {
	sig := oqs.Signature{}
	defer sig.Clean()

	if err := sig.Init(alg, secretKey); err != nil {
		return nil, fmt.Errorf("init signer %q: %w", alg, err)
	}

	details := sig.Details()
	if len(secretKey) != details.LengthSecretKey {
		return nil, fmt.Errorf("secret key length %d, want %d", len(secretKey), details.LengthSecretKey)
	}
	if len(publicKey) != details.LengthPublicKey {
		return nil, fmt.Errorf("public key length %d, want %d", len(publicKey), details.LengthPublicKey)
	}

	return &Signer{
		alg:       alg,
		secretKey: bytes.Clone(secretKey),
		publicKey: bytes.Clone(publicKey),
		details:   details,
	}, nil
}

func LoadOrGenerate(algorithm, secretKeyFile, publicKeyFile string) (*Signer, error) {
	sec := secretKeyFile
	pub := publicKeyFile
	if (sec == "") != (pub == "") {
		return nil, fmt.Errorf("secret_key_file and public_key_file must be set together")
	}

	if sec != "" {
		secExists := fileExists(sec)
		pubExists := fileExists(pub)
		if secExists != pubExists {
			return nil, fmt.Errorf("key files incomplete: secret=%t public=%t", secExists, pubExists)
		}
		if secExists && pubExists {
			return loadFromFiles(algorithm, sec, pub)
		}
	}

	s, err := Generate(algorithm)
	if err != nil {
		return nil, err
	}
	if sec != "" {
		if err := s.Save(sec, pub); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func loadFromFiles(alg, secretPath, publicPath string) (*Signer, error) {
	secretKey, err := os.ReadFile(secretPath)
	if err != nil {
		return nil, fmt.Errorf("read secret key: %w", err)
	}
	publicKey, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	return New(alg, secretKey, publicKey)
}

func (s *Signer) Save(secretPath, publicPath string) error {
	if err := writeFile(secretPath, s.secretKey, 0o600); err != nil {
		return fmt.Errorf("write secret key: %w", err)
	}
	if err := writeFile(publicPath, s.publicKey, 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

func (s *Signer) Algorithm() string { return s.alg }

func (s *Signer) PublicKey() []byte { return bytes.Clone(s.publicKey) }

func (s *Signer) Details() oqs.SignatureDetails { return s.details }

func (s *Signer) Sign(message []byte) ([]byte, error) {
	sig := oqs.Signature{}
	defer sig.Clean()

	// liboqs-go Clean() zeroes the key slice it was initialized with.
	sk := bytes.Clone(s.secretKey)
	if err := sig.Init(s.alg, sk); err != nil {
		return nil, fmt.Errorf("init signer %q: %w", s.alg, err)
	}

	signature, err := sig.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return signature, nil
}

// Verify checks that signature is valid for message under publicKey.
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, perm)
}
