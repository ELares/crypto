package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	c "github.com/ELares/crypto/pkg"
	p "github.com/ELares/crypto/pkg/pem"
)

type (
	// IED25519 interface for methods to generate ed25519 keys and conversion to PEM format
	IED25519 interface {
		Ed25519() (ed25519.PrivateKey, ed25519.PublicKey, error)
		Ed25519PEM() (ed25519.PrivateKey, p.PrivatePEM, ed25519.PublicKey, p.PublicPEM, error)

		FromPEMPrivateKey(p.PrivatePEM) (ed25519.PrivateKey, error)
		FromPEMPublicKey(p.PublicPEM) (ed25519.PublicKey, error)
		FromPEM(p.PrivatePEM, p.PublicPEM) (ed25519.PrivateKey, ed25519.PublicKey, error)

		ToPEMPrivateKey(ed25519.PrivateKey) (p.PrivatePEM, error)
		ToPEMPublicKey(ed25519.PublicKey) (p.PublicPEM, error)
		ToPEM(ed25519.PrivateKey, ed25519.PublicKey) (p.PrivatePEM, p.PublicPEM, error)
	}

	// ED25519 struct to implement the IED25519 methods
	ED25519 struct{}
)

// NewED25519 gets a new ED25519 pointer
func NewED25519() IED25519 {
	return &ED25519{}
}

// Ed25519 generates a new ed25519 private/public keys
func (e *ED25519) Ed25519() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pubkey, prvkey, err := ed25519.GenerateKey(rand.Reader)
	return prvkey, pubkey, err
}

// Ed25519PEM generates new ed25519 private/public pem keys
func (e *ED25519) Ed25519PEM() (ed25519.PrivateKey, p.PrivatePEM, ed25519.PublicKey, p.PublicPEM, error) {
	privateKey, publicKey, err := e.Ed25519()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	privatePEMKey, publicPEMKey, err := e.ToPEM(privateKey, publicKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return privateKey, privatePEMKey, publicKey, publicPEMKey, nil
}

// FromPEMPrivateKey takes a private pem key and converts it into a ed25519 private key
func (e *ED25519) FromPEMPrivateKey(privatePEM p.PrivatePEM) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(privatePEM)

	if block == nil || block.Type != c.PRIVATEKEY {
		return nil, c.ErrDecodePEMPrivateKey
	}

	genericPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return genericPrivateKey.(ed25519.PrivateKey), nil
}

// FromPEMPublicKey takes a public pem key and converts it into a ed25519 public key
func (e *ED25519) FromPEMPublicKey(publicPEM p.PublicPEM) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(publicPEM)

	if block == nil || block.Type != c.PUBLICKEY {
		return nil, c.ErrDecodePEMPublicKey
	}

	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return genericPublicKey.(ed25519.PublicKey), nil
}

// FromPEM takes pem keys and converts them into a ed25519 keys
func (e *ED25519) FromPEM(privatePEM p.PrivatePEM, publicPEM p.PublicPEM) (ed25519.PrivateKey, ed25519.PublicKey, error) {
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

// ToPEMPrivateKey converts a ed25519 private key into a private PEM key
func (e *ED25519) ToPEMPrivateKey(privateKey ed25519.PrivateKey) (p.PrivatePEM, error) {
	if privateKey == nil {
		return nil, c.ErrNilPrivateKey
	}

	x509Encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: c.PRIVATEKEY, Bytes: x509Encoded}), nil
}

// ToPEMPublicKey converts a ed25519 public key into a public PEM key
func (e *ED25519) ToPEMPublicKey(publicKey ed25519.PublicKey) (p.PublicPEM, error) {
	if publicKey == nil {
		return nil, c.ErrNilPublicKey
	}

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: c.PUBLICKEY, Bytes: x509EncodedPub}), nil
}

// ToPEM converts ed25519 private & public keys, into private & public PEM keys
func (e *ED25519) ToPEM(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) (p.PrivatePEM, p.PublicPEM, error) {
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
