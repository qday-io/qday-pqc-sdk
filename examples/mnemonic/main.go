package main

import (
	"fmt"
	"log"

	"github.com/qday-io/qday-pqc-sdk/pqc"
)

func main() {
	mnemonic, err := pqc.NewMnemonic(24)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := pqc.GenerateFromMnemonic(pqc.AlgMLDSA65, mnemonic, "")
	if err != nil {
		log.Fatal(err)
	}
	defer signer.Clean()

	msg := []byte("hello pqc")
	sig, err := signer.Sign(msg)
	if err != nil {
		log.Fatal(err)
	}
	ok, err := pqc.Verify(signer.Algorithm(), msg, sig, signer.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("mnemonic=%s\nalgorithm=%s valid=%v public_key_b64=%s\n",
		mnemonic, signer.Algorithm(), ok, pqc.EncodeBase64(signer.PublicKey()))
}
