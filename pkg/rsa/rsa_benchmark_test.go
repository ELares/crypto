package rsa

import (
	"testing"
)

func BenchmarkNewRSA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewRSA()
	}
}

func BenchmarkR2048(b *testing.B) {
	rsa := NewRSA()

	for i := 0; i < b.N; i++ {
		rsa.R2048()
	}
}

func BenchmarkR4096(b *testing.B) {
	rsa := NewRSA()

	for i := 0; i < b.N; i++ {
		rsa.R4096()
	}
}

func BenchmarkR2048PrivateKey(b *testing.B) {
	rsa := NewRSA()

	for i := 0; i < b.N; i++ {
		rsa.R2048()
	}
}

func BenchmarkR4096PrivateKey(b *testing.B) {
	rsa := NewRSA()

	for i := 0; i < b.N; i++ {
		rsa.R4096()
	}
}

func BenchmarkR2048PEM(b *testing.B) {
	rsa := NewRSA()

	for i := 0; i < b.N; i++ {
		rsa.R2048PEM()
	}
}

func BenchmarkR4096PEM(b *testing.B) {
	rsa := NewRSA()

	for i := 0; i < b.N; i++ {
		rsa.R4096PEM()
	}
}

func BenchmarkR2048PEMPrivateKey(b *testing.B) {
	rsa := NewRSA()

	for i := 0; i < b.N; i++ {
		rsa.R2048PEMPrivateKey()
	}
}

func BenchmarkR4096PEMPrivateKey(b *testing.B) {
	rsa := NewRSA()

	for i := 0; i < b.N; i++ {
		rsa.R4096PEMPrivateKey()
	}
}

func BenchmarkFromPEMPrivateKeyR2048(b *testing.B) {
	rsa := NewRSA()

	privateKey, _, _ := rsa.R2048()
	privateKeyPEM, _ := rsa.ToPEMPrivateKey(privateKey)

	for i := 0; i < b.N; i++ {
		rsa.FromPEMPrivateKey(privateKeyPEM)
	}
}

func BenchmarkFromPEMPrivateKeyR4096(b *testing.B) {
	rsa := NewRSA()

	privateKey, _, _ := rsa.R4096()
	privateKeyPEM, _ := rsa.ToPEMPrivateKey(privateKey)

	for i := 0; i < b.N; i++ {
		rsa.FromPEMPrivateKey(privateKeyPEM)
	}
}

func BenchmarkFromPEMPublicKeyR2048(b *testing.B) {
	rsa := NewRSA()

	_, publicKey, _ := rsa.R2048()
	publicKeyPEM, _ := rsa.ToPEMPublicKey(publicKey)

	for i := 0; i < b.N; i++ {
		rsa.FromPEMPublicKey(publicKeyPEM)
	}
}

func BenchmarkFromPEMPublicKeyR4096(b *testing.B) {
	rsa := NewRSA()

	_, publicKey, _ := rsa.R4096()
	publicKeyPEM, _ := rsa.ToPEMPublicKey(publicKey)

	for i := 0; i < b.N; i++ {
		rsa.FromPEMPublicKey(publicKeyPEM)
	}
}

func BenchmarkFromPEMR2048(b *testing.B) {
	rsa := NewRSA()

	_, privatePEM, _, publicPEM, _ := rsa.R2048PEM()

	for i := 0; i < b.N; i++ {
		rsa.FromPEM(privatePEM, publicPEM)
	}
}

func BenchmarkFromPEMR4096(b *testing.B) {
	rsa := NewRSA()

	_, privatePEM, _, publicPEM, _ := rsa.R4096PEM()

	for i := 0; i < b.N; i++ {
		rsa.FromPEM(privatePEM, publicPEM)
	}
}

func BenchmarkToPEMPrivateKeyR2048(b *testing.B) {
	rsa := NewRSA()

	pvkey, _ := rsa.R2048PrivateKey()

	for i := 0; i < b.N; i++ {
		rsa.ToPEMPrivateKey(pvkey)
	}
}

func BenchmarkToPEMPrivateKeyR4096(b *testing.B) {
	rsa := NewRSA()

	pvkey, _ := rsa.R4096PrivateKey()

	for i := 0; i < b.N; i++ {
		rsa.ToPEMPrivateKey(pvkey)
	}
}

func BenchmarkToPEMPublicKeyR2048(b *testing.B) {
	rsa := NewRSA()

	_, pubkey, _ := rsa.R2048()

	for i := 0; i < b.N; i++ {
		rsa.ToPEMPublicKey(pubkey)
	}
}

func BenchmarkToPEMPublicKeyR4096(b *testing.B) {
	rsa := NewRSA()

	_, pubkey, _ := rsa.R4096()

	for i := 0; i < b.N; i++ {
		rsa.ToPEMPublicKey(pubkey)
	}
}
