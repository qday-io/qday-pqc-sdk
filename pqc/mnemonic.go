package pqc

import (
	"fmt"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/sha3"
)

const mnemonicDomain = "qday-pqc-sdk/v1/"

// NewMnemonic returns a new BIP-39 English mnemonic.
// words must be 12, 15, 18, 21, or 24.
func NewMnemonic(words int) (string, error) {
	bits, err := mnemonicEntropyBits(words)
	if err != nil {
		return "", err
	}
	entropy, err := bip39.NewEntropy(bits)
	if err != nil {
		return "", fmt.Errorf("mnemonic entropy: %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("mnemonic: %w", err)
	}
	return mnemonic, nil
}

// ValidateMnemonic reports whether mnemonic is a valid BIP-39 English phrase.
func ValidateMnemonic(mnemonic string) error {
	if !bip39.IsMnemonicValid(mnemonic) {
		return ErrInvalidMnemonic
	}
	return nil
}

// GenerateFromMnemonic derives a key pair from a BIP-39 English mnemonic.
// passphrase is the optional BIP-39 passphrase; use "" when none is set.
//
// The same (mnemonic, passphrase, algorithm) tuple yields the same key pair
// for a given liboqs version. Different algorithms derive independently.
func GenerateFromMnemonic(alg, mnemonic, passphrase string) (*Signer, error) {
	alg, err := normalizeAlg(alg)
	if err != nil {
		return nil, err
	}
	if err := ValidateMnemonic(mnemonic); err != nil {
		return nil, err
	}

	seed := bip39.NewSeed(mnemonic, passphrase)
	defer wipe(seed)

	xof := sha3.NewShake256()
	_, _ = xof.Write([]byte(mnemonicDomain))
	_, _ = xof.Write([]byte(alg))
	_, _ = xof.Write([]byte{0})
	_, _ = xof.Write(seed)

	fill := func(out []byte, n int) {
		if n > len(out) {
			n = len(out)
		}
		if n <= 0 {
			return
		}
		_, _ = xof.Read(out[:n])
	}

	keygenMu.Lock()
	defer keygenMu.Unlock()

	if err := oqs.RandomBytesCustomAlgorithm(fill); err != nil {
		return nil, fmt.Errorf("mnemonic rng: %w", err)
	}
	defer func() {
		_ = oqs.RandomBytesSwitchAlgorithm("system")
	}()

	return generateLocked(alg)
}

func mnemonicEntropyBits(words int) (int, error) {
	switch words {
	case 12:
		return 128, nil
	case 15:
		return 160, nil
	case 18:
		return 192, nil
	case 21:
		return 224, nil
	case 24:
		return 256, nil
	default:
		return 0, ErrInvalidWordCount
	}
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
