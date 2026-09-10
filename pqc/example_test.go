package pqc_test

import (
	"fmt"
	"log"

	"github.com/qday-io/qday-pqc-sdk/pqc"
)

func Example() {
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
	fmt.Println(ok)
	// Output: true
}

func ExampleNew() {
	first, err := pqc.Generate(pqc.AlgMLDSA65)
	if err != nil {
		log.Fatal(err)
	}
	defer first.Clean()

	signer, err := pqc.New(first.Algorithm(), first.SecretKey(), first.PublicKey())
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
	fmt.Println(ok)
	// Output: true
}
