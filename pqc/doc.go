// Package pqc is a Go SDK for post-quantum signatures.
//
// It wraps [liboqs-go] (ML-DSA / FIPS 204 and other algorithms enabled in
// liboqs). Building requires CGO and a system liboqs installation.
//
// Typical local use:
//
//	signer, err := pqc.Generate(pqc.AlgMLDSA65)
//	if err != nil {
//		return err
//	}
//	sig, err := signer.Sign([]byte("hello pqc"))
//	if err != nil {
//		return err
//	}
//	ok, err := pqc.Verify(signer.Algorithm(), []byte("hello pqc"), sig, signer.PublicKey())
//
// Reconstruct a signer from key bytes with [New]:
//
//	signer, err := pqc.New(alg, secretKey, publicKey)
//
// Derive a key pair from a BIP-39 mnemonic with [GenerateFromMnemonic]:
//
//	mnemonic, err := pqc.NewMnemonic(24)
//	signer, err := pqc.GenerateFromMnemonic(pqc.AlgMLDSA65, mnemonic, "")
//
// [liboqs-go]: https://github.com/open-quantum-safe/liboqs-go
package pqc
