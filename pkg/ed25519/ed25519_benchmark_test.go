package ed25519

import "testing"

func BenchmarkNewED25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewED25519()
	}
}

func BenchmarkEd25519(b *testing.B) {
	ed := NewED25519()

	for i := 0; i < b.N; i++ {
		ed.Ed25519()
	}
}

func BenchmarkEd25519PrivateKey(b *testing.B) {
	ed := NewED25519()

	for i := 0; i < b.N; i++ {
		ed.Ed25519()
	}
}

func BenchmarkEd25519PEM(b *testing.B) {
	ed := NewED25519()

	for i := 0; i < b.N; i++ {
		ed.Ed25519PEM()
	}
}
func BenchmarkFromPEMPrivateKeyEd25519(b *testing.B) {
	ed := NewED25519()

	privateKey, _, _ := ed.Ed25519()
	privateKeyPEM, _ := ed.ToPEMPrivateKey(privateKey)

	for i := 0; i < b.N; i++ {
		ed.FromPEMPrivateKey(privateKeyPEM)
	}
}

func BenchmarkFromPEMPublicKeyEd25519(b *testing.B) {
	ed := NewED25519()

	_, publicKey, _ := ed.Ed25519()
	publicKeyPEM, _ := ed.ToPEMPublicKey(publicKey)

	for i := 0; i < b.N; i++ {
		ed.FromPEMPublicKey(publicKeyPEM)
	}
}

func BenchmarkFromPEMEd25519(b *testing.B) {
	ed := NewED25519()

	_, privatePEM, _, publicPEM, _ := ed.Ed25519PEM()

	for i := 0; i < b.N; i++ {
		ed.FromPEM(privatePEM, publicPEM)
	}
}

func BenchmarkToPEMPrivateKeyEd25519(b *testing.B) {
	ed := NewED25519()

	pvkey, _, _ := ed.Ed25519()

	for i := 0; i < b.N; i++ {
		ed.ToPEMPrivateKey(pvkey)
	}
}

func BenchmarkToPEMPublicKeyEd25519(b *testing.B) {
	ed := NewED25519()

	_, pubkey, _ := ed.Ed25519()

	for i := 0; i < b.N; i++ {
		ed.ToPEMPublicKey(pubkey)
	}
}
