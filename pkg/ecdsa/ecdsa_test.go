package ecdsa

import (
	"bytes"
	cecdsa "crypto/ecdsa"
	"errors"
	"math/big"
	"strings"
	"testing"

	p "github.com/ELares/crypto/pkg/pem"
	"github.com/stretchr/testify/assert"
)

func TestFromPEMPrivateKey(t *testing.T) {
	ecdsa := NewECDSA()

	testcases := []struct {
		name string

		privateKey string

		expectEqual bool
		expectError bool
	}{
		{
			name: "Valid Private Key",

			privateKey: "-----BEGIN PRIVATE KEY-----\nMIHcAgEBBEIAsNuHc/wbXZfrDcypuB4VZBv6TEUcq8gwIcAzGXDPEnCg9nD165VR\ntLGBZxiDF2exGI+ASBRDobJ3+4z+HloKGm6gBwYFK4EEACOhgYkDgYYABAHxs17A\nY2TKH6jPQNGaikh6Y6JyHA66rnDx0mN4ps/2dDPy4LzpFPzpdohmCFks+MH/XLHx\ndIbTl1HAEO/+mYsy5wAOAalWecPU67QLqsRNzm7wmC0O+6tmKsMxzZ7Yd+qswwE7\nUZseHYrITE4pqxOEexXLYhidtHQ+QXwDH1a18dGoEA==\n-----END PRIVATE KEY-----\n",

			expectEqual: true,
			expectError: false,
		},
		{
			name: "InValid Private Key: Header Not Right",

			privateKey: "-----BEGIN BLAHBLAHBLAHBLAH KEY-----\nMIHcAgEBBEIAsNuHc/wbXZfrDcypuB4VZBv6TEUcq8gwIcAzGXDPEnCg9nD165VR\ntLGBZxiDF2exGI+ASBRDobJ3+4z+HloKGm6gBwYFK4EEACOhgYkDgYYABAHxs17A\nY2TKH6jPQNGaikh6Y6JyHA66rnDx0mN4ps/2dDPy4LzpFPzpdohmCFks+MH/XLHx\ndIbTl1HAEO/+mYsy5wAOAalWecPU67QLqsRNzm7wmC0O+6tmKsMxzZ7Yd+qswwE7\nUZseHYrITE4pqxOEexXLYhidtHQ+QXwDH1a18dGoEA==\n-----END PRIVATE KEY-----\n",

			expectEqual: false,
			expectError: true,
		},
		{
			name: "InValid Private Key: Footer Not Right",

			privateKey: "-----BEGIN PRIVATE KEY-----\nMIHcAgEBBEIAsNuHc/wbXZfrDcypuB4VZBv6TEUcq8gwIcAzGXDPEnCg9nD165VR\ntLGBZxiDF2exGI+ASBRDobJ3+4z+HloKGm6gBwYFK4EEACOhgYkDgYYABAHxs17A\nY2TKH6jPQNGaikh6Y6JyHA66rnDx0mN4ps/2dDPy4LzpFPzpdohmCFks+MH/XLHx\ndIbTl1HAEO/+mYsy5wAOAalWecPU67QLqsRNzm7wmC0O+6tmKsMxzZ7Yd+qswwE7\nUZseHYrITE4pqxOEexXLYhidtHQ+QXwDH1a18dGoEA==\n-----END BLAHBLAHBLAH KEY-----\n",

			expectEqual: false,
			expectError: true,
		},
		{
			name: "InValid Private Key: Body Not Right",

			privateKey: "-----BEGIN PRIVATE KEY-----\nMIHcAgEBBEIAsNuHc/$$$$$$$$$$$$$$$$$$$$$$$$$$$$\ntLGBZxiDF2exGI+ASBRDobJ3+4z+HloKGm6gBwYFK4EEACOhgYkDgYYABAHxs17A\nY2TKH6jPQNGaikh6Y6JyHA66rnDx0mN4ps/2dDPy4LzpFPzpdohmCFks+MH/XLHx\ndIbTl1HAEO/+mYsy5wAOAalWecPU67QLqsRNzm7wmC0O+6tmKsMxzZ7Yd+qswwE7\nUZseHYrITE4pqxOEexXLYhidtHQ+QXwDH1a18dGoEA==\n-----END PRIVATE KEY-----\n",

			expectEqual: false,
			expectError: true,
		},
		{
			name: "InValid Private Key: Blank/Empty",

			privateKey:  "",
			expectEqual: false,
			expectError: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ecdsa.FromPEMPrivateKey([]byte(tc.privateKey))

			if tc.expectError {
				assert.NotNil(t, err)
			}

			if tc.expectEqual {
				pemPrivateKey, err := ecdsa.ToPEMPrivateKey(result)

				if err != nil {
					assert.Fail(t, "error expected to be nil")
				}

				assert.Equal(t, 0, strings.Compare(tc.privateKey, string(pemPrivateKey)))
			}
		})
	}
}

func TestFromPEMPublicKey(t *testing.T) {
	ecdsa := NewECDSA()

	testcases := []struct {
		name string

		publicKey string

		expectEqual bool
		expectError bool
	}{
		{
			name: "Valid Public Key",

			publicKey: "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAq5kUVO1YWwLBXWwoKMDCHvOA3D4w\nFmt0+HFl52qPOZiM0546rOPYItupnVwJ2xflnNJXDHP7C2+ywWq8wLmpP50AE7QY\no+nOHraYUsSXQHOz6ytHUP/f7cnXO4iPoLMRoREUXsuPnBG7Ad0e3SIs9aoN0hEt\ns0X2J8uUwaTMkQlOj5g=\n-----END PUBLIC KEY-----\n",

			expectEqual: true,
			expectError: false,
		},
		{
			name: "InValid Public Key: Header Not Right",

			publicKey: "-----BEGIN BLAH BLAH KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAq5kUVO1YWwLBXWwoKMDCHvOA3D4w\nFmt0+HFl52qPOZiM0546rOPYItupnVwJ2xflnNJXDHP7C2+ywWq8wLmpP50AE7QY\no+nOHraYUsSXQHOz6ytHUP/f7cnXO4iPoLMRoREUXsuPnBG7Ad0e3SIs9aoN0hEt\ns0X2J8uUwaTMkQlOj5g=\n-----END PUBLIC KEY-----\n",

			expectEqual: false,
			expectError: true,
		},
		{
			name: "InValid Public Key: Footer Not Right",

			publicKey: "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAq5kUVO1YWwLBXWwoKMDCHvOA3D4w\nFmt0+HFl52qPOZiM0546rOPYItupnVwJ2xflnNJXDHP7C2+ywWq8wLmpP50AE7QY\no+nOHraYUsSXQHOz6ytHUP/f7cnXO4iPoLMRoREUXsuPnBG7Ad0e3SIs9aoN0hEt\ns0X2J8uUwaTMkQlOj5g=\n-----END BLAH BLAH KEY-----\n",

			expectEqual: false,
			expectError: true,
		},
		{
			name: "InValid Public Key: Body Not Right",

			publicKey: "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgE******************************************OA3D4w\nFmt0+HFl52qPOZiM0546rOPYItupnVwJ2xflnNJXDHP7C2+ywWq8wLmpP50AE7QY\no+nOHraYUsSXQHOz6ytHUP/f7cnXO4iPoLMRoREUXsuPnBG7Ad0e3SIs9aoN0hEt\ns0X2J8uUwaTMkQlOj5g=\n-----END PUBLIC KEY-----\n",

			expectEqual: false,
			expectError: true,
		},
		{
			name: "InValid Public Key: Blank/Empty",

			publicKey:   "",
			expectEqual: false,
			expectError: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ecdsa.FromPEMPublicKey([]byte(tc.publicKey))
			if tc.expectError {
				assert.NotNil(t, err, err.Error())
			}

			if tc.expectEqual {
				pemPublicKey, err := ecdsa.ToPEMPublicKey(result)

				if err != nil {
					assert.Fail(t, "error expected to be nil")
				}

				assert.Equal(t, 0, strings.Compare(tc.publicKey, string(pemPublicKey)))
			}
		})
	}
}

func TestToPEMPrivateKey(t *testing.T) {
	ecdsa := NewECDSA()

	p521, _ := ecdsa.P521PrivateKey()
	p384, _ := ecdsa.P384PrivateKey()
	p256, _ := ecdsa.P256PrivateKey()
	p224, _ := ecdsa.P224PrivateKey()

	testcases := []struct {
		name string
		key  *cecdsa.PrivateKey

		isValid bool
	}{
		{
			name: "Valid P521",
			key:  p521,

			isValid: true,
		},
		{
			name: "Valid P384",
			key:  p384,

			isValid: true,
		},
		{
			name: "Valid P256",
			key:  p256,

			isValid: true,
		},
		{
			name: "Valid P224",
			key:  p224,

			isValid: true,
		},
		{
			name: "Invalid Nil",
			key:  nil,

			isValid: false,
		},
		{
			name: "Invalid empty",
			key:  &cecdsa.PrivateKey{},

			isValid: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			pemKey, err := ecdsa.ToPEMPrivateKey(tc.key)

			if tc.isValid {
				assert.Nil(t, err)
				testKey, err := ecdsa.FromPEMPrivateKey(pemKey)
				assert.NotNil(t, testKey)
				assert.NotEmpty(t, testKey)
				assert.Nil(t, err)
			} else {
				assert.Nil(t, pemKey)
				assert.NotNil(t, err)
			}
		})
	}
}

func TestToPEMPublicKey(t *testing.T) {
	ecdsa := NewECDSA()

	_, p521, _ := ecdsa.P521()
	_, p384, _ := ecdsa.P384()
	_, p256, _ := ecdsa.P256()
	_, p224, _ := ecdsa.P224()

	testcases := []struct {
		name string
		key  *cecdsa.PublicKey

		isValid bool
	}{
		{
			name: "Valid P521",
			key:  p521,

			isValid: true,
		},
		{
			name: "Valid P384",
			key:  p384,

			isValid: true,
		},
		{
			name: "Valid P256",
			key:  p256,

			isValid: true,
		},
		{
			name: "Valid P224",
			key:  p224,

			isValid: true,
		},
		{
			name: "Invalid Nil",
			key:  nil,

			isValid: false,
		},
		{
			name: "Invalid XY nil",
			key:  &cecdsa.PublicKey{},

			isValid: false,
		},
		{
			name: "Invalid Y nil",
			key:  &cecdsa.PublicKey{X: &big.Int{}},

			isValid: false,
		},
		{
			name: "Invalid Y nil",
			key:  &cecdsa.PublicKey{X: &big.Int{}, Y: &big.Int{}},

			isValid: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			pemKey, err := ecdsa.ToPEMPublicKey(tc.key)

			if tc.isValid {
				assert.Nil(t, err)
				testKey, err := ecdsa.FromPEMPublicKey(pemKey)
				assert.NotNil(t, testKey)
				assert.NotEmpty(t, testKey)
				assert.Nil(t, err)
			} else {
				assert.Nil(t, pemKey)
				assert.NotNil(t, err)
			}
		})
	}
}

func TestGenerateKeys(t *testing.T) {
	ecdsa := &ECDSA{}

	testcases := []struct {
		name   string
		method func() (*cecdsa.PrivateKey, error)

		isError bool
	}{
		{
			name:   "Valid P521",
			method: ecdsa.P521PrivateKey,

			isError: false,
		},

		{
			name:   "Valid P384",
			method: ecdsa.P384PrivateKey,

			isError: false,
		},

		{
			name:   "Valid P256",
			method: ecdsa.P256PrivateKey,

			isError: false,
		},

		{
			name:   "Valid P224",
			method: ecdsa.P224PrivateKey,

			isError: false,
		},

		{
			name:   "Invalid method",
			method: func() (*cecdsa.PrivateKey, error) { return nil, errors.New("mock_fail") },

			isError: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			prvKey, pubKey, err := ecdsa.generateKeys(tc.method)

			if tc.isError {
				assert.Nil(t, prvKey)
				assert.Nil(t, pubKey)
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)

				prvPEM, err := ecdsa.ToPEMPrivateKey(prvKey)
				assert.Nil(t, err)
				assert.NotNil(t, prvPEM)
				assert.NotEmpty(t, prvPEM)

				pubPEM, err := ecdsa.ToPEMPublicKey(pubKey)
				assert.Nil(t, err)
				assert.NotNil(t, pubPEM)
				assert.NotEmpty(t, pubPEM)

				prvKey2, err := ecdsa.FromPEMPrivateKey(prvPEM)
				assert.Nil(t, err)
				assert.NotNil(t, prvKey2)

				pubKey2, err := ecdsa.FromPEMPublicKey(pubPEM)
				assert.Nil(t, err)
				assert.NotNil(t, pubKey2)
			}
		})
	}
}

func TestECDSAP(t *testing.T) {
	ecdsa := &ECDSA{}

	testcases := []struct {
		name   string
		method func() (*cecdsa.PrivateKey, *cecdsa.PublicKey, error)

		isError bool
	}{
		{
			name:    "Valid P521",
			method:  ecdsa.P521,
			isError: false,
		},

		{
			name:    "Valid P384",
			method:  ecdsa.P384,
			isError: false,
		},

		{
			name:    "Valid P256",
			method:  ecdsa.P256,
			isError: false,
		},

		{
			name:    "Valid P224",
			method:  ecdsa.P224,
			isError: false,
		},

		{
			name:    "Invalid P",
			method:  func() (*cecdsa.PrivateKey, *cecdsa.PublicKey, error) { return nil, nil, errors.New("mock_error") },
			isError: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			prvKey, pubKey, err := tc.method()

			if tc.isError {
				assert.Nil(t, prvKey)
				assert.Nil(t, pubKey)
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)

				prvPEM, pubPEM, err := ecdsa.ToPEM(prvKey, pubKey)
				assert.Nil(t, err)
				assert.NotNil(t, prvPEM)
				assert.NotEmpty(t, prvPEM)
				assert.NotNil(t, pubPEM)
				assert.NotEmpty(t, pubPEM)

				prvKey2, pubKey2, err := ecdsa.FromPEM(prvPEM, pubPEM)
				assert.Nil(t, err)
				assert.NotNil(t, prvKey2)
				assert.NotNil(t, pubKey2)
			}
		})
	}
}

func TestECDSAPPEM(t *testing.T) {
	ecdsa := &ECDSA{}

	testcases := []struct {
		name   string
		method func() (*cecdsa.PrivateKey, p.PrivatePEM, *cecdsa.PublicKey, p.PublicPEM, error)

		isError bool
	}{
		{
			name:    "Valid P521PEM",
			method:  ecdsa.P521PEM,
			isError: false,
		},

		{
			name:    "Valid P384PEM",
			method:  ecdsa.P384PEM,
			isError: false,
		},

		{
			name:    "Valid P256PEM",
			method:  ecdsa.P256PEM,
			isError: false,
		},

		{
			name:    "Valid P224PEM",
			method:  ecdsa.P224PEM,
			isError: false,
		},

		{
			name: "Invalid P",
			method: func() (*cecdsa.PrivateKey, p.PrivatePEM, *cecdsa.PublicKey, p.PublicPEM, error) {
				return nil, nil, nil, nil, errors.New("mock_error")
			},
			isError: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			prvKey, prvPEM, pubKey, pubPEM, err := tc.method()

			if tc.isError {
				assert.Nil(t, prvKey)
				assert.Nil(t, prvPEM)
				assert.Nil(t, pubKey)
				assert.Nil(t, pubPEM)
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.NotNil(t, prvPEM)
				assert.NotEmpty(t, prvPEM)
				assert.NotNil(t, pubPEM)
				assert.NotEmpty(t, pubPEM)

				prvKey2, pubKey2, err := ecdsa.FromPEM(prvPEM, pubPEM)
				assert.Nil(t, err)
				assert.NotNil(t, prvKey2)
				assert.NotNil(t, pubKey2)

				prvPEM2, pubPEM2, err := ecdsa.ToPEM(prvKey, pubKey)
				assert.Nil(t, err)
				assert.NotNil(t, prvPEM2)
				assert.NotEmpty(t, prvPEM2)
				assert.NotNil(t, pubPEM2)
				assert.NotEmpty(t, pubPEM2)

				assert.Equal(t, 0, bytes.Compare(prvPEM, prvPEM2))
				assert.Equal(t, 0, bytes.Compare(pubPEM, pubPEM2))
			}
		})
	}
}

func TestECDSAPPEMPrivateKey(t *testing.T) {
	ecdsa := &ECDSA{}

	testcases := []struct {
		name   string
		method func() (*cecdsa.PrivateKey, p.PrivatePEM, error)

		isError bool
	}{
		{
			name:    "Valid P521PEMPrivateKey",
			method:  ecdsa.P521PEMPrivateKey,
			isError: false,
		},

		{
			name:    "Valid P384PEMPrivateKey",
			method:  ecdsa.P384PEMPrivateKey,
			isError: false,
		},

		{
			name:    "Valid P256PEMPrivateKey",
			method:  ecdsa.P256PEMPrivateKey,
			isError: false,
		},

		{
			name:    "Valid P224PEMPrivateKey",
			method:  ecdsa.P224PEMPrivateKey,
			isError: false,
		},

		{
			name: "Invalid P",
			method: func() (*cecdsa.PrivateKey, p.PrivatePEM, error) {
				return nil, nil, errors.New("mock_error")
			},
			isError: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			prvKey, prvPEM, err := tc.method()

			if tc.isError {
				assert.Nil(t, prvKey)
				assert.Nil(t, prvPEM)
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
				assert.NotNil(t, prvPEM)
				assert.NotEmpty(t, prvPEM)

				prvKey2, err := ecdsa.FromPEMPrivateKey(prvPEM)
				assert.Nil(t, err)
				assert.NotNil(t, prvKey2)

				prvPEM2, err := ecdsa.ToPEMPrivateKey(prvKey)
				assert.Nil(t, err)
				assert.NotNil(t, prvPEM2)
				assert.NotEmpty(t, prvPEM2)

				assert.Equal(t, 0, bytes.Compare(prvPEM, prvPEM2))
			}
		})
	}
}
