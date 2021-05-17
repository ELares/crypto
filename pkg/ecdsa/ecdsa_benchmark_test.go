package ecdsa

import "testing"

func BenchmarkNewECDSA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewECDSA()
	}
}

func BenchmarkP521(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P521()
	}
}

func BenchmarkP384(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P384()
	}
}

func BenchmarkP256(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P256()
	}
}

func BenchmarkP224(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P224()
	}
}

func BenchmarkP521PrivateKey(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P521()
	}
}

func BenchmarkP384PrivateKey(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P384()
	}
}

func BenchmarkP256PrivateKey(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P256()
	}
}

func BenchmarkP224PrivateKey(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P224()
	}
}

func BenchmarkP521PEM(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P521PEM()
	}
}

func BenchmarkP384PEM(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P384PEM()
	}
}

func BenchmarkP256PEM(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P256PEM()
	}
}

func BenchmarkP224PEM(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P224PEM()
	}
}

func BenchmarkP521PEMPrivateKey(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P521PEMPrivateKey()
	}
}

func BenchmarkP384PEMPrivateKey(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P384PEMPrivateKey()
	}
}

func BenchmarkP256PEMPrivateKey(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P256PEMPrivateKey()
	}
}

func BenchmarkP224PEMPrivateKey(b *testing.B) {
	ecdsa := NewECDSA()

	for i := 0; i < b.N; i++ {
		ecdsa.P224PEMPrivateKey()
	}
}

func BenchmarkFromPEMPrivateKeyP521(b *testing.B) {
	ecdsa := NewECDSA()

	privateKey, _, _ := ecdsa.P521()
	privateKeyPEM, _ := ecdsa.ToPEMPrivateKey(privateKey)

	for i := 0; i < b.N; i++ {
		ecdsa.FromPEMPrivateKey(privateKeyPEM)
	}
}

func BenchmarkFromPEMPrivateKeyP384(b *testing.B) {
	ecdsa := NewECDSA()

	privateKey, _, _ := ecdsa.P384()
	privateKeyPEM, _ := ecdsa.ToPEMPrivateKey(privateKey)

	for i := 0; i < b.N; i++ {
		ecdsa.FromPEMPrivateKey(privateKeyPEM)
	}
}

func BenchmarkFromPEMPrivateKeyP256(b *testing.B) {
	ecdsa := NewECDSA()

	privateKey, _, _ := ecdsa.P256()
	privateKeyPEM, _ := ecdsa.ToPEMPrivateKey(privateKey)

	for i := 0; i < b.N; i++ {
		ecdsa.FromPEMPrivateKey(privateKeyPEM)
	}
}

func BenchmarkFromPEMPrivateKeyP224(b *testing.B) {
	ecdsa := NewECDSA()

	privateKey, _, _ := ecdsa.P224()
	privateKeyPEM, _ := ecdsa.ToPEMPrivateKey(privateKey)

	for i := 0; i < b.N; i++ {
		ecdsa.FromPEMPrivateKey(privateKeyPEM)
	}
}

func BenchmarkFromPEMPublicKeyP521(b *testing.B) {
	ecdsa := NewECDSA()

	_, publicKey, _ := ecdsa.P521()
	publicKeyPEM, _ := ecdsa.ToPEMPublicKey(publicKey)

	for i := 0; i < b.N; i++ {
		ecdsa.FromPEMPublicKey(publicKeyPEM)
	}
}

func BenchmarkFromPEMPublicKeyP384(b *testing.B) {
	ecdsa := NewECDSA()

	_, publicKey, _ := ecdsa.P384()
	publicKeyPEM, _ := ecdsa.ToPEMPublicKey(publicKey)

	for i := 0; i < b.N; i++ {
		ecdsa.FromPEMPublicKey(publicKeyPEM)
	}
}

func BenchmarkFromPEMPublicKeyP256(b *testing.B) {
	ecdsa := NewECDSA()

	_, publicKey, _ := ecdsa.P256()
	publicKeyPEM, _ := ecdsa.ToPEMPublicKey(publicKey)

	for i := 0; i < b.N; i++ {
		ecdsa.FromPEMPublicKey(publicKeyPEM)
	}
}

func BenchmarkFromPEMPublicKeyP224(b *testing.B) {
	ecdsa := NewECDSA()

	_, publicKey, _ := ecdsa.P224()
	publicKeyPEM, _ := ecdsa.ToPEMPublicKey(publicKey)

	for i := 0; i < b.N; i++ {
		ecdsa.FromPEMPublicKey(publicKeyPEM)
	}
}

func BenchmarkFromPEMP521(b *testing.B) {
	ecdsa := NewECDSA()

	_, privatePEM, _, publicPEM, _ := ecdsa.P521PEM()

	for i := 0; i < b.N; i++ {
		ecdsa.FromPEM(privatePEM, publicPEM)
	}
}

func BenchmarkFromPEMP384(b *testing.B) {
	ecdsa := NewECDSA()

	_, privatePEM, _, publicPEM, _ := ecdsa.P384PEM()

	for i := 0; i < b.N; i++ {
		ecdsa.FromPEM(privatePEM, publicPEM)
	}
}

func BenchmarkFromPEMP256(b *testing.B) {
	ecdsa := NewECDSA()

	_, privatePEM, _, publicPEM, _ := ecdsa.P256PEM()

	for i := 0; i < b.N; i++ {
		ecdsa.FromPEM(privatePEM, publicPEM)
	}
}

func BenchmarkFromPEMP224(b *testing.B) {
	ecdsa := NewECDSA()

	_, privatePEM, _, publicPEM, _ := ecdsa.P224PEM()

	for i := 0; i < b.N; i++ {
		ecdsa.FromPEM(privatePEM, publicPEM)
	}
}

func BenchmarkToPEMPrivateKeyP521(b *testing.B) {
	ecdsa := NewECDSA()

	pvkey, _ := ecdsa.P521PrivateKey()

	for i := 0; i < b.N; i++ {
		ecdsa.ToPEMPrivateKey(pvkey)
	}
}

func BenchmarkToPEMPrivateKeyP384(b *testing.B) {
	ecdsa := NewECDSA()

	pvkey, _ := ecdsa.P384PrivateKey()

	for i := 0; i < b.N; i++ {
		ecdsa.ToPEMPrivateKey(pvkey)
	}
}

func BenchmarkToPEMPrivateKeyP256(b *testing.B) {
	ecdsa := NewECDSA()

	pvkey, _ := ecdsa.P256PrivateKey()

	for i := 0; i < b.N; i++ {
		ecdsa.ToPEMPrivateKey(pvkey)
	}
}

func BenchmarkToPEMPrivateKeyP224(b *testing.B) {
	ecdsa := NewECDSA()

	pvkey, _ := ecdsa.P224PrivateKey()

	for i := 0; i < b.N; i++ {
		ecdsa.ToPEMPrivateKey(pvkey)
	}
}

func BenchmarkToPEMPublicKeyP521(b *testing.B) {
	ecdsa := NewECDSA()

	_, pubkey, _ := ecdsa.P521()

	for i := 0; i < b.N; i++ {
		ecdsa.ToPEMPublicKey(pubkey)
	}
}

func BenchmarkToPEMPublicKeyP384(b *testing.B) {
	ecdsa := NewECDSA()

	_, pubkey, _ := ecdsa.P384()

	for i := 0; i < b.N; i++ {
		ecdsa.ToPEMPublicKey(pubkey)
	}
}

func BenchmarkToPEMPublicKeyP256(b *testing.B) {
	ecdsa := NewECDSA()

	_, pubkey, _ := ecdsa.P256()

	for i := 0; i < b.N; i++ {
		ecdsa.ToPEMPublicKey(pubkey)
	}
}

func BenchmarkToPEMPublicKeyP224(b *testing.B) {
	ecdsa := NewECDSA()

	_, pubkey, _ := ecdsa.P224()

	for i := 0; i < b.N; i++ {
		ecdsa.ToPEMPublicKey(pubkey)
	}
}
