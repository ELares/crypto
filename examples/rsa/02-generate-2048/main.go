package main

import (
	"fmt"

	"github.com/ELares/crypto/pkg/rsa"
)

func main() {
	irsa := rsa.NewRSA()

	// Generate a brand new RSA Private & Public Key
	prvKey, pubKey, err := irsa.R2048()
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	// Convert the Private & Public Key to a PEM format
	prvPEM, pubPEM, err := irsa.ToPEM(prvKey, pubKey)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	// Output the PEM files
	fmt.Printf("This is the private key:\n%s\n", string(prvPEM))
	fmt.Printf("This is the public key:\n%s\n", string(pubPEM))

	// Convert the Public key to a JWK
	jwk, err := irsa.ToJWKRS256(pubKey, "some-random-id")
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	fmt.Printf("This is the JWK:\n%s\n", string(jwk))
}
