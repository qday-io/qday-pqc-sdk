package main

import (
	"fmt"
	"log"

	"github.com/qday-io/qday-pqc-sdk/pqc"
)

func main() {
	signer, err := pqc.Generate(pqc.AlgMLDSA65)
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
	if !ok {
		log.Fatal("verify failed")
	}

	loaded, err := pqc.New(signer.Algorithm(), signer.SecretKey(), signer.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	defer loaded.Clean()
	ok, err = pqc.Verify(loaded.Algorithm(), msg, sig, loaded.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("algorithm=%s valid=%v signature_b64=%s\n",
		signer.Algorithm(), ok, pqc.EncodeBase64(sig))
}
