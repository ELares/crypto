# crypto
A repo to simplify the usage of crypto libraries.

# ECDSA
* Generate private & public key
* Convert private public keys to PEM format
* Convert public key to JWK
## Example
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

## Output
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

# RSA
* Generate private & public key
* Convert private public keys to PEM format
* Convert public key to JWK
## Example
```go
package main

import (
	"fmt"

	"github.com/ELares/crypto/pkg/rsa"
)

func main() {
	irsa := rsa.NewRSA()

	// Generate a brand new RSA Private & Public Key
	prvKey, pubKey, err := irsa.R4096()
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
	jwk, err := irsa.ToJWKRS512(pubKey, "some-random-id")
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	fmt.Printf("This is the JWK:\n%s\n", string(jwk))
}

```

## Output
```console
This is the private key:
-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----

This is the public key:
-----BEGIN PUBLIC KEY-----
MIICCgKCAgEA0Aq3xJfamlNqoflhXjCEsGhdO0JHKFRH0IlV+YFIAtfVTWDGbMZo
uhun2mcNQYy6DTw+j367ignegETq4buXJgoAd0qV4gl2bolU5J6kRnv7zv2XZO5x
PfBqajzaPJdWIByG+vXA8/LLTp3E8C+TVCYQyAuLw8Z7K+WfvexmQi4swjPnGz2x
0u4t7GlgNeSzcV5w2LLOL63fdbOYHn9fPEWUfc2bWVF/JTGZxgpyNxG3iabJueex
ojmM/gRlMD9olUSZQWIxsXp7iu9XmiT+4oKymZqYmKiikcsw9NRGCIWXEPZbZc4p
POBZhi/Dw/3KI0DW3icS05Pl+qR63pIMLiUCpC51h3JyHor162/OxqDTqCG9Veq0
dzEoOKDAFrCaq7cTAZtDwrLqKPNSVHI4cvU+muCcXZ71dGnzvMGQ5HhHGZGItS05
7Y0flh6o7KpUCZcA/wjZAe/SqnJ4yU1zbV8DU1gpRJKfHS2nbzJVW8yFMjykofnK
nXEwmfUG+DM/kewXHtxRaMkfv2xkDKRk8cOX/uYmCYm8l99N6Ub+KiTUbemfhWKw
1HARHx6n2692SWwX7/0m33sIYtc0MCDQMY/Pi2PBzLHpGRo+LxBJAh+oryzsXqv2
P1DJ7gwp0xNkSQLmNZk+LX/zm9I0U9yMYPK8WxNFz587UXRBoE/GHusCAwEAAQ==
-----END PUBLIC KEY-----

This is the JWK:
{"use":"sig","kty":"RSA","kid":"some-random-id","alg":"RS512","n":"0Aq3xJfamlNqoflhXjCEsGhdO0JHKFRH0IlV-YFIAtfVTWDGbMZouhun2mcNQYy6DTw-j367ignegETq4buXJgoAd0qV4gl2bolU5J6kRnv7zv2XZO5xPfBqajzaPJdWIByG-vXA8_LLTp3E8C-TVCYQyAuLw8Z7K-WfvexmQi4swjPnGz2x0u4t7GlgNeSzcV5w2LLOL63fdbOYHn9fPEWUfc2bWVF_JTGZxgpyNxG3iabJueexojmM_gRlMD9olUSZQWIxsXp7iu9XmiT-4oKymZqYmKiikcsw9NRGCIWXEPZbZc4pPOBZhi_Dw_3KI0DW3icS05Pl-qR63pIMLiUCpC51h3JyHor162_OxqDTqCG9Veq0dzEoOKDAFrCaq7cTAZtDwrLqKPNSVHI4cvU-muCcXZ71dGnzvMGQ5HhHGZGItS057Y0flh6o7KpUCZcA_wjZAe_SqnJ4yU1zbV8DU1gpRJKfHS2nbzJVW8yFMjykofnKnXEwmfUG-DM_kewXHtxRaMkfv2xkDKRk8cOX_uYmCYm8l99N6Ub-KiTUbemfhWKw1HARHx6n2692SWwX7_0m33sIYtc0MCDQMY_Pi2PBzLHpGRo-LxBJAh-oryzsXqv2P1DJ7gwp0xNkSQLmNZk-LX_zm9I0U9yMYPK8WxNFz587UXRBoE_GHus","e":"AQAB"}
```

# ED25519
* Generate private & public key
* Convert private public keys to PEM format
## Example
```go
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

```

## Output
```console
This is the private key:
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILza3htO6jyZPUX6rUVTTYqKvZTgR59IdxkFYkr3ZMh8
-----END PRIVATE KEY-----

This is the public key:
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAmZtz4YGXqN+/0Hf4A1NXrC90tdt2N13jNBWpeAHAT0Y=
-----END PUBLIC KEY-----
```