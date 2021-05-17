package crypto

import (
	"errors"
)

var (
	// ErrDecodePEMPrivateKey error when trying to decode a private pem
	ErrDecodePEMPrivateKey = errors.New("failed to decode PEM block containing private key")

	// ErrDecodePEMPublicKey error when trying to decode a public pem
	ErrDecodePEMPublicKey = errors.New("failed to decode PEM block containing public key")

	// ErrNilPrivateKey error when the private key is nil
	ErrNilPrivateKey = errors.New("private key is nil")

	// ErrNilPrivateKeyD error when the private key D is nil
	ErrNilPrivateKeyD = errors.New("private key D is nil")

	// ErrNilPrivateKeyN error when the private key N is nil
	ErrNilPrivateKeyN = errors.New("private key N is nil")

	// ErrNilPublicKey error when the public key is nil
	ErrNilPublicKey = errors.New("public key is nil")

	// ErrNilPublicKeyN error when the public key N is nil
	ErrNilPublicKeyN = errors.New("public key N is nil")

	// ErrNilPublicKeyX error when the public key X is nil
	ErrNilPublicKeyX = errors.New("public key X is nil")

	// ErrNilPublicKeyY error when the public key Y is nil
	ErrNilPublicKeyY = errors.New("public key Y is nil")

	// ErrNilPublicKeyCurve error when the public key Curve is nil
	ErrNilPublicKeyCurve = errors.New("public key Curve is nil")
)
