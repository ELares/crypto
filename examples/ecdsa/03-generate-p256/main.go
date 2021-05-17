package main

import (
	"fmt"

	e "github.com/ELares/crypto/pkg/ecdsa"
)

func main() {
	iecdsa := e.NewECDSA()

	// Generate a brand new ECDSA Private & Public Key
	prvKey, pubKey, err := iecdsa.P256()
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	// Convert the Private & Public Key to a PEM format
	prvPEM, pubPEM, err := iecdsa.ToPEM(prvKey, pubKey)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	// Output the PEM files
	fmt.Printf("This is the private key:\n%s\n\n", string(prvPEM))
	fmt.Printf("This is the public key:\n%s\n", string(pubPEM))

	// Convert the Public key to a JWK
	jwk, err := iecdsa.ToJWKES256(pubKey, "some-random-id")
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	fmt.Printf("This is the JWK:\n%s\n", string(jwk))
}
