package main

import (
	"fmt"

	"github.com/ELares/crypto/pkg/ed25519"
)

func main() {
	ied := ed25519.NewED25519()

	// Generate a brand new ED25519 Private & Public Key
	prvKey, pubKey, err := ied.Ed25519()
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	// Convert the Private & Public Key to a PEM format
	prvPEM, pubPEM, err := ied.ToPEM(prvKey, pubKey)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	// Output the PEM files
	fmt.Printf("This is the private key:\n%s\n", string(prvPEM))
	fmt.Printf("This is the public key:\n%s\n", string(pubPEM))
}
