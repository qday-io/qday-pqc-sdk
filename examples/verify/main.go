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

	v, err := pqc.NewVerifier(signer.Algorithm(), signer.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	ok, err := v.Verify(msg, sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("algorithm=%s valid=%v\n", v.Algorithm(), ok)
}
