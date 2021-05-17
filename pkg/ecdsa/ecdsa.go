package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	c "github.com/ELares/crypto/pkg"
	p "github.com/ELares/crypto/pkg/pem"
	jose "gopkg.in/square/go-jose.v2"
)

type (
	// IECDSA interface for methods to generate ecdsa keys and conversion to PEM format
	IECDSA interface {
		P521() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error)
		P384() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error)
		P256() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error)
		P224() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error)

		P521PrivateKey() (*ecdsa.PrivateKey, error)
		P384PrivateKey() (*ecdsa.PrivateKey, error)
		P256PrivateKey() (*ecdsa.PrivateKey, error)
		P224PrivateKey() (*ecdsa.PrivateKey, error)

		P521PEM() (*ecdsa.PrivateKey, p.PrivatePEM, *ecdsa.PublicKey, p.PublicPEM, error)
		P384PEM() (*ecdsa.PrivateKey, p.PrivatePEM, *ecdsa.PublicKey, p.PublicPEM, error)
		P256PEM() (*ecdsa.PrivateKey, p.PrivatePEM, *ecdsa.PublicKey, p.PublicPEM, error)
		P224PEM() (*ecdsa.PrivateKey, p.PrivatePEM, *ecdsa.PublicKey, p.PublicPEM, error)

		P521PEMPrivateKey() (*ecdsa.PrivateKey, p.PrivatePEM, error)
		P384PEMPrivateKey() (*ecdsa.PrivateKey, p.PrivatePEM, error)
		P256PEMPrivateKey() (*ecdsa.PrivateKey, p.PrivatePEM, error)
		P224PEMPrivateKey() (*ecdsa.PrivateKey, p.PrivatePEM, error)

		FromPEMPrivateKey(p.PrivatePEM) (*ecdsa.PrivateKey, error)
		FromPEMPublicKey(p.PublicPEM) (*ecdsa.PublicKey, error)
		FromPEM(p.PrivatePEM, p.PublicPEM) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error)

		ToPEMPrivateKey(*ecdsa.PrivateKey) (p.PrivatePEM, error)
		ToPEMPublicKey(*ecdsa.PublicKey) (p.PublicPEM, error)
		ToPEM(*ecdsa.PrivateKey, *ecdsa.PublicKey) (p.PrivatePEM, p.PublicPEM, error)

		ToJWK(publicKey *ecdsa.PublicKey, id string, algo jose.SignatureAlgorithm) ([]byte, error)
	}

	// ECDSA struct to implement the IECDSA methods
	ECDSA struct{}
)

// NewECDSA get a new ECDSA pointer
func NewECDSA() IECDSA {
	return &ECDSA{}
}

// P521 generates new ECDSA P521 private/public keys
func (e *ECDSA) P521() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	return e.generateKeys(e.P521PrivateKey)
}

// P384 generates new ECDSA P384 private/public keys
func (e *ECDSA) P384() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	return e.generateKeys(e.P384PrivateKey)
}

// P256 generates new ECDSA P256 private/public keys
func (e *ECDSA) P256() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	return e.generateKeys(e.P256PrivateKey)
}

// P224 generates new ECDSA P224 private/public keys
func (e *ECDSA) P224() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	return e.generateKeys(e.P224PrivateKey)
}

// P521PrivateKey generates a new ECDSA P521 private key
func (e *ECDSA) P521PrivateKey() (*ecdsa.PrivateKey, error) {
	return e.generateKey(elliptic.P521())
}

// P384PrivateKey generates a new ECDSA P384 private key
func (e *ECDSA) P384PrivateKey() (*ecdsa.PrivateKey, error) {
	return e.generateKey(elliptic.P384())
}

// P256PrivateKey generates a new ECDSA P256 private key
func (e *ECDSA) P256PrivateKey() (*ecdsa.PrivateKey, error) {
	return e.generateKey(elliptic.P256())
}

// P224PrivateKey generates a new ECDSA P224 private key
func (e *ECDSA) P224PrivateKey() (*ecdsa.PrivateKey, error) {
	return e.generateKey(elliptic.P224())
}

// P521PEM generates new ECDSA P521 private/public pem keys
func (e *ECDSA) P521PEM() (*ecdsa.PrivateKey, p.PrivatePEM, *ecdsa.PublicKey, p.PublicPEM, error) {
	return e.generatePEMKeys(e.P521PEMPrivateKey)
}

// P384PEM generates new ECDSA P384 private/public pem keys
func (e *ECDSA) P384PEM() (*ecdsa.PrivateKey, p.PrivatePEM, *ecdsa.PublicKey, p.PublicPEM, error) {
	return e.generatePEMKeys(e.P384PEMPrivateKey)
}

// P256PEM generates new ECDSA P256 private/public pem keys
func (e *ECDSA) P256PEM() (*ecdsa.PrivateKey, p.PrivatePEM, *ecdsa.PublicKey, p.PublicPEM, error) {
	return e.generatePEMKeys(e.P256PEMPrivateKey)
}

// P224PEM generates new ECDSA P224 private/public pem keys
func (e *ECDSA) P224PEM() (*ecdsa.PrivateKey, p.PrivatePEM, *ecdsa.PublicKey, p.PublicPEM, error) {
	return e.generatePEMKeys(e.P224PEMPrivateKey)
}

// P521PEMPrivateKey generates a new ECDSA P521 private PEM key
func (e *ECDSA) P521PEMPrivateKey() (*ecdsa.PrivateKey, p.PrivatePEM, error) {
	return e.generatePrivatePEMKey(e.P521PrivateKey)
}

// P384PEMPrivateKey generates a new ECDSA P384 private PEM key
func (e *ECDSA) P384PEMPrivateKey() (*ecdsa.PrivateKey, p.PrivatePEM, error) {
	return e.generatePrivatePEMKey(e.P384PrivateKey)
}

// P256PEMPrivateKey generates a new ECDSA P256 private PEM key
func (e *ECDSA) P256PEMPrivateKey() (*ecdsa.PrivateKey, p.PrivatePEM, error) {
	return e.generatePrivatePEMKey(e.P256PrivateKey)
}

// P224PEMPrivateKey generates a new ECDSA P224 private PEM key
func (e *ECDSA) P224PEMPrivateKey() (*ecdsa.PrivateKey, p.PrivatePEM, error) {
	return e.generatePrivatePEMKey(e.P224PrivateKey)
}

// FromPEMPrivateKey takes a private pem key and converts it into a ecdsa private key
func (e *ECDSA) FromPEMPrivateKey(privatePEM p.PrivatePEM) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(privatePEM)

	if block == nil || block.Type != c.PRIVATEKEY {
		return nil, c.ErrDecodePEMPrivateKey
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

// FromPEMPublicKey takes a public pem key and converts it into a ecdsa public key
func (e *ECDSA) FromPEMPublicKey(publicPEM p.PublicPEM) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(publicPEM)

	if block == nil || block.Type != c.PUBLICKEY {
		return nil, c.ErrDecodePEMPublicKey
	}

	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return genericPublicKey.(*ecdsa.PublicKey), nil
}

// FromPEM takes pem keys and converts them into a ecdsa keys
func (e *ECDSA) FromPEM(privatePEM p.PrivatePEM, publicPEM p.PublicPEM) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := e.FromPEMPrivateKey(privatePEM)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := e.FromPEMPublicKey(publicPEM)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

// ToPEMPrivateKey converts a ECDSA private key into a private PEM key
func (e *ECDSA) ToPEMPrivateKey(privateKey *ecdsa.PrivateKey) (p.PrivatePEM, error) {
	if privateKey == nil {
		return nil, c.ErrNilPrivateKey
	}

	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: c.PRIVATEKEY, Bytes: x509Encoded}), nil
}

// ToPEMPublicKey converts a ECDSA public key into a public PEM key
func (e *ECDSA) ToPEMPublicKey(publicKey *ecdsa.PublicKey) (p.PublicPEM, error) {
	if publicKey == nil {
		return nil, c.ErrNilPublicKey
	}

	if publicKey.X == nil {
		return nil, c.ErrNilPublicKeyX
	}

	if publicKey.Y == nil {
		return nil, c.ErrNilPublicKeyY
	}

	if publicKey.Curve == nil {
		return nil, c.ErrNilPublicKeyCurve
	}

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: c.PUBLICKEY, Bytes: x509EncodedPub}), nil
}

// ToPEM converts ECDSA private & public keys, into private & public PEM keys
func (e *ECDSA) ToPEM(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (p.PrivatePEM, p.PublicPEM, error) {
	prvPEM, err := e.ToPEMPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	pubPEM, err := e.ToPEMPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}

	return prvPEM, pubPEM, nil
}

// ToJWK converts ECDSA public key into a jwk
func (e *ECDSA) ToJWK(publicKey *ecdsa.PublicKey, id string, algo jose.SignatureAlgorithm) ([]byte, error) {
	jwk := jose.JSONWebKey{
		Use:       "sig",
		Algorithm: string(algo),
		Key:       publicKey,
		KeyID:     id,
	}

	return jwk.MarshalJSON()
}

// generateKey wrapper for ecdsa.GenerateKey() for unit-test mocking purposes
func (e *ECDSA) generateKey(algorithm elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(algorithm, rand.Reader)
}

// generateKeys generates a new ECDSA private/public key given a genKey method
func (e *ECDSA) generateKeys(genKeyMethod func() (*ecdsa.PrivateKey, error)) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := genKeyMethod()
	if err != nil {
		return nil, nil, err
	}

	return privateKey, &privateKey.PublicKey, nil
}

// generatePrivatePEMKey generates a new ECDSA private pem key
func (e *ECDSA) generatePrivatePEMKey(keyGenMethod func() (*ecdsa.PrivateKey, error)) (*ecdsa.PrivateKey, p.PrivatePEM, error) {
	privateKey, err := keyGenMethod()
	if err != nil {
		return nil, nil, err
	}

	privatePEMKey, err := e.ToPEMPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, privatePEMKey, nil
}

// generatePEMKeys generates new ECDSA private/public pem keys
func (e *ECDSA) generatePEMKeys(keyGenMethod func() (*ecdsa.PrivateKey, p.PrivatePEM, error)) (*ecdsa.PrivateKey, p.PrivatePEM, *ecdsa.PublicKey, p.PublicPEM, error) {
	privateKey, privatePEMKey, err := keyGenMethod()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	publicKey := &privateKey.PublicKey
	publicPEMKey, err := e.ToPEMPublicKey(publicKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return privateKey, privatePEMKey, publicKey, publicPEMKey, nil
}
