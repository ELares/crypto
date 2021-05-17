# crypto
A repo to simplify the usage of crypto libraries.

## ECDSA
* Generate a P521 private & public key
* Convert private public keys to PEM format
* Convert public key to JWK
### Example
```go
package main

import (
	"fmt"

	e "github.com/ELares/crypto/pkg/ecdsa"
)

func main() {
	iecdsa := e.NewECDSA()

	// Generate a brand new ECDSA Private & Public Key
	prvKey, pubKey, err := iecdsa.P521()
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
	fmt.Printf("This is the private key:\n%s\n", string(prvPEM))
	fmt.Printf("This is the public key:\n%s\n", string(pubPEM))

	// Convert the Public key to a JWK
	jwk, err := iecdsa.ToJWKES512(pubKey, "some-random-id")
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	fmt.Printf("This is the JWK:\n%s\n", string(jwk))
}
```

### Output
```console
This is the private key:
-----BEGIN PRIVATE KEY-----
MIHcAgEBBEIA8n0+TVjXcGR+MH+g5sgv4lFBXtXVC2q/TJsxupYY5x18ZNNyTLlw
m2k1emerkQQGig1+t5tPAC5s1HMLsJo3SYCgBwYFK4EEACOhgYkDgYYABACFFo/j
ANkhp66OSs1YFRC/5NSkwgYBwWovUrjIQMr74DLN1kxEH/27dTqGO7lTp6SlYoYP
teh+hsDk5ruY3fxlRQGFrn/gMeg0bSQFW8Oeg04bA43a8uWi5gnkxMad7M20YMvv
gJ+uAS1Y92hKa9En7kwsqp9fKRYEiswSJDWUwLta7A==
-----END PRIVATE KEY-----

This is the public key:
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAhRaP4wDZIaeujkrNWBUQv+TUpMIG
AcFqL1K4yEDK++AyzdZMRB/9u3U6hju5U6ekpWKGD7XofobA5Oa7mN38ZUUBha5/
4DHoNG0kBVvDnoNOGwON2vLlouYJ5MTGnezNtGDL74CfrgEtWPdoSmvRJ+5MLKqf
XykWBIrMEiQ1lMC7Wuw=
-----END PUBLIC KEY-----

This is the JWK:
{"use":"sig","kty":"EC","kid":"some-random-id","crv":"P-521","alg":"ES512","x":"AIUWj-MA2SGnro5KzVgVEL_k1KTCBgHBai9SuMhAyvvgMs3WTEQf_bt1OoY7uVOnpKVihg-16H6GwOTmu5jd_GVF","y":"AYWuf-Ax6DRtJAVbw56DThsDjdry5aLmCeTExp3szbRgy--An64BLVj3aEpr0SfuTCyqn18pFgSKzBIkNZTAu1rs"}
```

