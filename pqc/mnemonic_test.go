package pqc

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const testMnemonic12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestNewMnemonic(t *testing.T) {
	for _, words := range []int{12, 15, 18, 21, 24} {
		mn, err := NewMnemonic(words)
		if err != nil {
			t.Fatalf("words=%d: %v", words, err)
		}
		if got := len(strings.Fields(mn)); got != words {
			t.Fatalf("words=%d: got %d tokens", words, got)
		}
		if err := ValidateMnemonic(mn); err != nil {
			t.Fatalf("words=%d: invalid mnemonic: %v", words, err)
		}
	}
}

func TestNewMnemonicRejectsWordCount(t *testing.T) {
	if _, err := NewMnemonic(11); !errors.Is(err, ErrInvalidWordCount) {
		t.Fatalf("got %v, want ErrInvalidWordCount", err)
	}
}

func TestValidateMnemonic(t *testing.T) {
	if err := ValidateMnemonic(testMnemonic12); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMnemonic("not a mnemonic"); !errors.Is(err, ErrInvalidMnemonic) {
		t.Fatalf("got %v, want ErrInvalidMnemonic", err)
	}
}

func TestGenerateFromMnemonicDeterministic(t *testing.T) {
	a, err := GenerateFromMnemonic(AlgMLDSA65, testMnemonic12, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Clean)
	b, err := GenerateFromMnemonic(AlgMLDSA65, testMnemonic12, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Clean)

	if !bytes.Equal(a.PublicKey(), b.PublicKey()) {
		t.Fatal("same mnemonic should yield the same public key")
	}
	if !bytes.Equal(a.SecretKey(), b.SecretKey()) {
		t.Fatal("same mnemonic should yield the same secret key")
	}

	msg := []byte("mnemonic sign")
	sig, err := a.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(a.Algorithm(), msg, sig, b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature from first signer should verify with second public key")
	}
}

func TestGenerateFromMnemonicPassphraseChangesKey(t *testing.T) {
	plain, err := GenerateFromMnemonic(AlgMLDSA65, testMnemonic12, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(plain.Clean)
	secret, err := GenerateFromMnemonic(AlgMLDSA65, testMnemonic12, "pass")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(secret.Clean)
	if bytes.Equal(plain.PublicKey(), secret.PublicKey()) {
		t.Fatal("passphrase should change the derived key")
	}
}

func TestGenerateFromMnemonicDifferentAlgorithms(t *testing.T) {
	a, err := GenerateFromMnemonic(AlgMLDSA44, testMnemonic12, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Clean)
	b, err := GenerateFromMnemonic(AlgMLDSA65, testMnemonic12, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Clean)
	if bytes.Equal(a.PublicKey(), b.PublicKey()) {
		t.Fatal("different algorithms should not share a public key")
	}
}

func TestGenerateFromMnemonicInvalid(t *testing.T) {
	if _, err := GenerateFromMnemonic(AlgMLDSA65, "not a mnemonic", ""); !errors.Is(err, ErrInvalidMnemonic) {
		t.Fatalf("got %v, want ErrInvalidMnemonic", err)
	}
	if _, err := GenerateFromMnemonic("", testMnemonic12, ""); !errors.Is(err, ErrAlgorithmRequired) {
		t.Fatalf("got %v, want ErrAlgorithmRequired", err)
	}
}
