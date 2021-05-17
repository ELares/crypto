package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	c "github.com/ELares/crypto/pkg"
	p "github.com/ELares/crypto/pkg/pem"
)

type (
	// IRSA interface for methods to generate rsa keys and conversion to PEM format
	IRSA interface {
		R2048() (*rsa.PrivateKey, *rsa.PublicKey, error)
		R4096() (*rsa.PrivateKey, *rsa.PublicKey, error)

		R2048PrivateKey() (*rsa.PrivateKey, error)
		R4096PrivateKey() (*rsa.PrivateKey, error)

		R2048PEM() (*rsa.PrivateKey, p.PrivatePEM, *rsa.PublicKey, p.PublicPEM, error)
		R4096PEM() (*rsa.PrivateKey, p.PrivatePEM, *rsa.PublicKey, p.PublicPEM, error)

		R2048PEMPrivateKey() (*rsa.PrivateKey, p.PrivatePEM, error)
		R4096PEMPrivateKey() (*rsa.PrivateKey, p.PrivatePEM, error)

		FromPEMPrivateKey(p.PrivatePEM) (*rsa.PrivateKey, error)
		FromPEMPublicKey(p.PublicPEM) (*rsa.PublicKey, error)
		FromPEM(p.PrivatePEM, p.PublicPEM) (*rsa.PrivateKey, *rsa.PublicKey, error)

		ToPEMPrivateKey(*rsa.PrivateKey) (p.PrivatePEM, error)
		ToPEMPublicKey(*rsa.PublicKey) (p.PublicPEM, error)
		ToPEM(*rsa.PrivateKey, *rsa.PublicKey) (p.PrivatePEM, p.PublicPEM, error)
	}

	// RSA struct to implement the IRSA methods
	RSA struct{}
)

// NewRSA gets a new RSA pointer
func NewRSA() IRSA {
	return &RSA{}
}

// R2048 generates a new RSA-2048 private/public keys
func (r *RSA) R2048() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	return r.generateKeys(r.R2048PrivateKey)
}

// R4096 generates a new RSA-4096 private/public keys
func (r *RSA) R4096() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	return r.generateKeys(r.R4096PrivateKey)
}

// R2048PrivateKey generates a new RSA-2048 private key
func (r *RSA) R2048PrivateKey() (*rsa.PrivateKey, error) {
	return r.generateKey(2048)
}

// R4096PrivateKey generates a new RSA-4096 private key
func (r *RSA) R4096PrivateKey() (*rsa.PrivateKey, error) {
	return r.generateKey(4096)
}

// R2048PEM generates new RSA-2048 private/public pem keys
func (r *RSA) R2048PEM() (*rsa.PrivateKey, p.PrivatePEM, *rsa.PublicKey, p.PublicPEM, error) {
	return r.generatePEMKeys(r.R2048PEMPrivateKey)
}

// R4096PEM generates new RSA-4096 private/public pem keys
func (r *RSA) R4096PEM() (*rsa.PrivateKey, p.PrivatePEM, *rsa.PublicKey, p.PublicPEM, error) {
	return r.generatePEMKeys(r.R4096PEMPrivateKey)
}

// R2048PEMPrivateKey generates a new RSA-2048 private PEM key
func (r *RSA) R2048PEMPrivateKey() (*rsa.PrivateKey, p.PrivatePEM, error) {
	return r.generatePrivatePEMKey(r.R2048PrivateKey)
}

// R4096PEMPrivateKey generates a new RSA-4096 private PEM key
func (r *RSA) R4096PEMPrivateKey() (*rsa.PrivateKey, p.PrivatePEM, error) {
	return r.generatePrivatePEMKey(r.R4096PrivateKey)
}

// FromPEMPrivateKey takes a private pem key and converts it into a rsa private key
func (r *RSA) FromPEMPrivateKey(privatePEM p.PrivatePEM) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privatePEM)

	if block == nil || block.Type != c.PRIVATEKEY {
		return nil, c.ErrDecodePEMPrivateKey
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// FromPEMPublicKey takes a public pem key and converts it into a rsa public key
func (r *RSA) FromPEMPublicKey(publicPEM p.PublicPEM) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicPEM)

	if block == nil || block.Type != c.PUBLICKEY {
		return nil, c.ErrDecodePEMPublicKey
	}

	genericPublicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return genericPublicKey, nil
}

// FromPEM takes pem keys and converts them into a rsa keys
func (r *RSA) FromPEM(privatePEM p.PrivatePEM, publicPEM p.PublicPEM) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := r.FromPEMPrivateKey(privatePEM)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := r.FromPEMPublicKey(publicPEM)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

// ToPEMPrivateKey converts a RSA private key into a private PEM key
func (r *RSA) ToPEMPrivateKey(privateKey *rsa.PrivateKey) (p.PrivatePEM, error) {
	if privateKey == nil {
		return nil, c.ErrNilPrivateKey
	}

	if privateKey.D == nil {
		return nil, c.ErrNilPrivateKeyD
	}

	if privateKey.N == nil {
		return nil, c.ErrNilPrivateKeyN
	}

	x509Encoded := x509.MarshalPKCS1PrivateKey(privateKey)

	return pem.EncodeToMemory(&pem.Block{Type: c.PRIVATEKEY, Bytes: x509Encoded}), nil
}

// ToPEMPublicKey converts a RSA public key into a public PEM key
func (r *RSA) ToPEMPublicKey(publicKey *rsa.PublicKey) (p.PublicPEM, error) {
	if publicKey == nil {
		return nil, c.ErrNilPublicKey
	}

	if publicKey.N == nil {
		return nil, c.ErrNilPublicKeyN
	}

	x509EncodedPub := x509.MarshalPKCS1PublicKey(publicKey)

	return pem.EncodeToMemory(&pem.Block{Type: c.PUBLICKEY, Bytes: x509EncodedPub}), nil
}

// ToPEM converts rsa private & public keys, into private & public PEM keys
func (r *RSA) ToPEM(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) (p.PrivatePEM, p.PublicPEM, error) {
	prvPEM, err := r.ToPEMPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	pubPEM, err := r.ToPEMPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}

	return prvPEM, pubPEM, nil
}

// generateKey wrapper for rsa.GenerateKey() for unit-test mocking purposes
func (r *RSA) generateKey(size int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, size)
}

// generateKeys generates a new RSA private/public key given a genKey method
func (r *RSA) generateKeys(genKeyMethod func() (*rsa.PrivateKey, error)) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := genKeyMethod()
	if err != nil {
		return nil, nil, err
	}

	return privateKey, &privateKey.PublicKey, nil
}

// generatePrivatePEMKey generates a new RSA private pem key
func (r *RSA) generatePrivatePEMKey(keyGenMethod func() (*rsa.PrivateKey, error)) (*rsa.PrivateKey, p.PrivatePEM, error) {
	privateKey, err := keyGenMethod()
	if err != nil {
		return nil, nil, err
	}

	privatePEMKey, err := r.ToPEMPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, privatePEMKey, nil
}

// generatePEMKeys generates new RSA private/public pem keys
func (r *RSA) generatePEMKeys(keyGenMethod func() (*rsa.PrivateKey, p.PrivatePEM, error)) (*rsa.PrivateKey, p.PrivatePEM, *rsa.PublicKey, p.PublicPEM, error) {
	privateKey, privatePEMKey, err := keyGenMethod()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	publicKey := &privateKey.PublicKey
	publicPEMKey, err := r.ToPEMPublicKey(publicKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return privateKey, privatePEMKey, publicKey, publicPEMKey, nil
}
