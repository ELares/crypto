package rsa

import (
	"bytes"
	crsa "crypto/rsa"
	"errors"
	"math/big"
	"strings"
	"testing"

	p "github.com/ELares/crypto/pkg/pem"
	"github.com/stretchr/testify/assert"
)

func TestRSAFromPEMPrivateKey(t *testing.T) {
	rsa := NewRSA()

	testcases := []struct {
		name string

		privateKey string

		expectEqual bool
		expectError bool
	}{
		{
			name: "Valid Private Key",

			privateKey: "-----BEGIN PRIVATE KEY-----\nMIIEpQIBAAKCAQEAvKvt+KT1e6x/K0Gbb1cxLQeG4DAeHSkxv8PeQjBg+zLjlDBJ\nCtS2Sp4SfPzSpLyYgnS5d0HIbZDirPzbz+2sozhdk2Sx938ODTFmRYLmn2SPDq+9\nfQXVAVxG4cu3gQffkiNXmjK+RA5LD9nuL/EiPB3ISPC7LEmtVFjrwc6eJegh5dvW\ni4aOSjT4UmZiANXRIWr02ZJRUSpFw/yAv7Q2wY0w/FOu4tI7jQ3NL+sPqonGmQ5/\nwlX1DtD4ZPyqZ0Vil1zGIjNjsj8AKWrjK077csXi1BaBL5MmvNljNVJV1fn0/EPG\ng/9MFJk+beKccVf39ZInVcLdFFkm0fmRYosm/QIDAQABAoIBAQCFhjPzbWMiNJEH\nXvYPFSkDUjlc/hDB2H6R1Z+9PhnUjU5MeOOom6OrKTWyaQb2eVaBtPPw94hOKmSR\nwp4aCH3OQbzP7Eqa+rtKEPTtKtfmZDduUGeNTIxT2yd68z6aPaU2+nYr9c97wJXU\n0QnlugTdgMJXBK+ihz343Ll0vrJj5i5+F9W68BYC/A4z3U+QU17xFUzdqAJoimBR\nfe6+kNhxan1+WG5vO608MkFB0jaMcS8XHufV9GkHVN8zuRxAR7BeRqQgFdbTFyM7\n+nKWZ0k2Xs7GGWU2W8FhzUq5XiYyvIBW95LX4U7JbSnIHV1uKpm/cRrRnD35ZLSl\nw8KW61ctAoGBANI9XVnNgnUqW3e7vFdav9ir+oulhs1QZgJ7KuXFB3BaOKDTYPnj\nxL+E0eRZVwWlA2BJQEXEXEhaSgVxbmNF5Sc4WklOczJO9zALFiAy300hD98Prua/\nkXzu+0IJAVNKTQFvQd3D6YrK5q7UZubQPCeGyc17D3+WwIBZktoBbXT3AoGBAOW8\nyC9EKbmQnNeJpXrpc6KPz1i+kCYeZuxenShkP6jx0gyrdm5e4EnJ8ZkUuxUB3fav\nBFnbYLDRkkFrOlZg7BkYYGkm0cdPFFBw08uakRkeL7POg/ddfohMN2YrM8O2VPsr\nsCZcrYx2UqzNO7gJ1eNadevbk/Hpegn07KlgzqqrAoGBAL3RX85r6WSl2K2zF+p6\n6gnTxMN+sMYA2AlXcTTA/uVm4Af8sWsNRZ9xaRxVuWdERFcT6+7RykwdEQX3EyaY\nfbw6efID3ahHeZCsAc8Sf2ChADZyb4Sw48e78aj+fm7X/8zSydJTRzHj3gFtjnbI\n/fbmEJ/wgt68mpOHzDn+3fejAoGBALHVAfhkgQ/dOys0p12PXC1XuJ7vU9HN8snB\nK1Ha19RE691W1GP3GRLFOTjP7UkDmvea3nlX8W6tqtLs18mJWPjL/8UlgXkQY58o\n1ylhyjNxRGeg0lImkw2aQb/abUVv3DRYyw/G6agy5yhP7Yw2QNSub11VKR43JnqS\nlqc+AnvlAoGAWk4U51dYQzggSY9VJMXuEIUE30avKMS2aataeNwiSXWrF875iY61\nYoHBzRlFU05zu172Lt3ebB+piYU8fxC14PW7rJ/s+oBH6JkBkjjSbShfISqr+m/z\n++OlJe/YWHuh440ar9pnF2XhqbQWklNmSMotI+B8VTbi5id0EDxK+pg=\n-----END PRIVATE KEY-----\n",

			expectEqual: true,
			expectError: false,
		},
		{
			name: "InValid Private Key: Header Not Right",

			privateKey: "-----BEGIN LX3K,.XLKDFLJKLK KEY-----\nMIIEpQIBAAKCAQEAvKvt+KT1e6x/K0Gbb1cxLQeG4DAeHSkxv8PeQjBg+zLjlDBJ\nCtS2Sp4SfPzSpLyYgnS5d0HIbZDirPzbz+2sozhdk2Sx938ODTFmRYLmn2SPDq+9\nfQXVAVxG4cu3gQffkiNXmjK+RA5LD9nuL/EiPB3ISPC7LEmtVFjrwc6eJegh5dvW\ni4aOSjT4UmZiANXRIWr02ZJRUSpFw/yAv7Q2wY0w/FOu4tI7jQ3NL+sPqonGmQ5/\nwlX1DtD4ZPyqZ0Vil1zGIjNjsj8AKWrjK077csXi1BaBL5MmvNljNVJV1fn0/EPG\ng/9MFJk+beKccVf39ZInVcLdFFkm0fmRYosm/QIDAQABAoIBAQCFhjPzbWMiNJEH\nXvYPFSkDUjlc/hDB2H6R1Z+9PhnUjU5MeOOom6OrKTWyaQb2eVaBtPPw94hOKmSR\nwp4aCH3OQbzP7Eqa+rtKEPTtKtfmZDduUGeNTIxT2yd68z6aPaU2+nYr9c97wJXU\n0QnlugTdgMJXBK+ihz343Ll0vrJj5i5+F9W68BYC/A4z3U+QU17xFUzdqAJoimBR\nfe6+kNhxan1+WG5vO608MkFB0jaMcS8XHufV9GkHVN8zuRxAR7BeRqQgFdbTFyM7\n+nKWZ0k2Xs7GGWU2W8FhzUq5XiYyvIBW95LX4U7JbSnIHV1uKpm/cRrRnD35ZLSl\nw8KW61ctAoGBANI9XVnNgnUqW3e7vFdav9ir+oulhs1QZgJ7KuXFB3BaOKDTYPnj\nxL+E0eRZVwWlA2BJQEXEXEhaSgVxbmNF5Sc4WklOczJO9zALFiAy300hD98Prua/\nkXzu+0IJAVNKTQFvQd3D6YrK5q7UZubQPCeGyc17D3+WwIBZktoBbXT3AoGBAOW8\nyC9EKbmQnNeJpXrpc6KPz1i+kCYeZuxenShkP6jx0gyrdm5e4EnJ8ZkUuxUB3fav\nBFnbYLDRkkFrOlZg7BkYYGkm0cdPFFBw08uakRkeL7POg/ddfohMN2YrM8O2VPsr\nsCZcrYx2UqzNO7gJ1eNadevbk/Hpegn07KlgzqqrAoGBAL3RX85r6WSl2K2zF+p6\n6gnTxMN+sMYA2AlXcTTA/uVm4Af8sWsNRZ9xaRxVuWdERFcT6+7RykwdEQX3EyaY\nfbw6efID3ahHeZCsAc8Sf2ChADZyb4Sw48e78aj+fm7X/8zSydJTRzHj3gFtjnbI\n/fbmEJ/wgt68mpOHzDn+3fejAoGBALHVAfhkgQ/dOys0p12PXC1XuJ7vU9HN8snB\nK1Ha19RE691W1GP3GRLFOTjP7UkDmvea3nlX8W6tqtLs18mJWPjL/8UlgXkQY58o\n1ylhyjNxRGeg0lImkw2aQb/abUVv3DRYyw/G6agy5yhP7Yw2QNSub11VKR43JnqS\nlqc+AnvlAoGAWk4U51dYQzggSY9VJMXuEIUE30avKMS2aataeNwiSXWrF875iY61\nYoHBzRlFU05zu172Lt3ebB+piYU8fxC14PW7rJ/s+oBH6JkBkjjSbShfISqr+m/z\n++OlJe/YWHuh440ar9pnF2XhqbQWklNmSMotI+B8VTbi5id0EDxK+pg=\n-----END PRIVATE KEY-----\n",

			expectEqual: false,
			expectError: true,
		},
		{
			name: "InValid Private Key: Footer Not Right",

			privateKey: "-----BEGIN PRIVATE KEY-----\nMIIEpQIBAAKCAQEAvKvt+KT1e6x/K0Gbb1cxLQeG4DAeHSkxv8PeQjBg+zLjlDBJ\nCtS2Sp4SfPzSpLyYgnS5d0HIbZDirPzbz+2sozhdk2Sx938ODTFmRYLmn2SPDq+9\nfQXVAVxG4cu3gQffkiNXmjK+RA5LD9nuL/EiPB3ISPC7LEmtVFjrwc6eJegh5dvW\ni4aOSjT4UmZiANXRIWr02ZJRUSpFw/yAv7Q2wY0w/FOu4tI7jQ3NL+sPqonGmQ5/\nwlX1DtD4ZPyqZ0Vil1zGIjNjsj8AKWrjK077csXi1BaBL5MmvNljNVJV1fn0/EPG\ng/9MFJk+beKccVf39ZInVcLdFFkm0fmRYosm/QIDAQABAoIBAQCFhjPzbWMiNJEH\nXvYPFSkDUjlc/hDB2H6R1Z+9PhnUjU5MeOOom6OrKTWyaQb2eVaBtPPw94hOKmSR\nwp4aCH3OQbzP7Eqa+rtKEPTtKtfmZDduUGeNTIxT2yd68z6aPaU2+nYr9c97wJXU\n0QnlugTdgMJXBK+ihz343Ll0vrJj5i5+F9W68BYC/A4z3U+QU17xFUzdqAJoimBR\nfe6+kNhxan1+WG5vO608MkFB0jaMcS8XHufV9GkHVN8zuRxAR7BeRqQgFdbTFyM7\n+nKWZ0k2Xs7GGWU2W8FhzUq5XiYyvIBW95LX4U7JbSnIHV1uKpm/cRrRnD35ZLSl\nw8KW61ctAoGBANI9XVnNgnUqW3e7vFdav9ir+oulhs1QZgJ7KuXFB3BaOKDTYPnj\nxL+E0eRZVwWlA2BJQEXEXEhaSgVxbmNF5Sc4WklOczJO9zALFiAy300hD98Prua/\nkXzu+0IJAVNKTQFvQd3D6YrK5q7UZubQPCeGyc17D3+WwIBZktoBbXT3AoGBAOW8\nyC9EKbmQnNeJpXrpc6KPz1i+kCYeZuxenShkP6jx0gyrdm5e4EnJ8ZkUuxUB3fav\nBFnbYLDRkkFrOlZg7BkYYGkm0cdPFFBw08uakRkeL7POg/ddfohMN2YrM8O2VPsr\nsCZcrYx2UqzNO7gJ1eNadevbk/Hpegn07KlgzqqrAoGBAL3RX85r6WSl2K2zF+p6\n6gnTxMN+sMYA2AlXcTTA/uVm4Af8sWsNRZ9xaRxVuWdERFcT6+7RykwdEQX3EyaY\nfbw6efID3ahHeZCsAc8Sf2ChADZyb4Sw48e78aj+fm7X/8zSydJTRzHj3gFtjnbI\n/fbmEJ/wgt68mpOHzDn+3fejAoGBALHVAfhkgQ/dOys0p12PXC1XuJ7vU9HN8snB\nK1Ha19RE691W1GP3GRLFOTjP7UkDmvea3nlX8W6tqtLs18mJWPjL/8UlgXkQY58o\n1ylhyjNxRGeg0lImkw2aQb/abUVv3DRYyw/G6agy5yhP7Yw2QNSub11VKR43JnqS\nlqc+AnvlAoGAWk4U51dYQzggSY9VJMXuEIUE30avKMS2aataeNwiSXWrF875iY61\nYoHBzRlFU05zu172Lt3ebB+piYU8fxC14PW7rJ/s+oBH6JkBkjjSbShfISqr+m/z\n++OlJe/YWHuh440ar9pnF2XhqbQWklNmSMotI+B8VTbi5id0EDxK+pg=\n-----END PRIVATE 22SDFSDF2----\n",

			expectEqual: false,
			expectError: true,
		},
		{
			name: "InValid Private Key: Body Not Right",

			privateKey: "-----BEGIN PRIVATE KEY-----\nMIIEpQIBAAKCAQEAvKvt+KT1e6x/K0Gbb1cxLQeG4DAeHSkxv8PeQjBg+zLjlDBJ\nCtS2Sp4SfPzSpLyYgnS5d0HIbZDirPzbz+2sozhdk2Sx938ODTFmRYLmn2SPDq+9\nfQXVAVxG4cu3gQffkiNXmjK+RA5LD9nuL/EiPB3ISPC7LEmtVFjrwc6eJegh5dvW\ni4aOSjT4UmZiANXRIWr02ZJRUSpFw/yAv7Q2wY0w/FOu4tI7jQ3NL+sPqonGmQ5/\nwlX1DtD4ZPyqZ0Vil1zGIjNjsj8AKWrjK077csXi1BaBL5MmvNljNVJV1fn0/EPG\ng/9MFJk+beKccVf39ZInVcLdFFkm0fmRYosm/QIDAQABAoIBAQCFhjPzbWMiNJEH\nXvYPFSkDUjlc/hDB2H6R1Z+9PhnUjU5MeOOom6OrKTWyaQb2eVaBtPPw94hOKmSR\nwp4aCH3OQbzP7Eqa+rtKEPTtKtfmZDduUGeNTIxT2yd68z6aPaU2+nYr9c97wJXU\n0QnlugTdgMJXBK+ihz343Ll0vrJj5i5+F9W68BYC/A4z3U+QU17xFUzdqAJoimBR\nfe6+kNhxan1+WG5vO608MkFB0jaMcS8XHufV9GkHVN8zuRxAR7BeRqQgFdbTFyM7\n+nKWZ0k2Xs7GGWU2W8FhzUq5XiYyvIBW95LX4U7JbSnIHV1uKpm/cRrRnD35ZLSl\nw8KW61ctAoGBANI9XVnNgnUqW3e7vFdav9ir+oulhs1QZgJ7KuXFB3BaOKDTYPnj\nxL+E0eRZVwWlA2BJQEXEXEhaSgVxbmNF5Sc4WklOczJO9zALFiAy300hD98Prua/\nkXzu+0IJAVNKTQFvQd3D6YrK5q7UZubQPCeGyc17D3+WwIBZktoBbXT3AoGBAOW8\nyC9EKbmQnNeJpXrpc6KPz1i+kCYeZuxenShkP6jx0gyrdm5e4EnJ8ZkUuxUB3fav\nBFnbYLDRkkFrOlZg7BkYYGkm0cdPFFBw08uakRkeL7POg/ddfohMN2YrM8O2VPsr\nsCZcrYx2UqzNO7gJ1eNadevbk/Hpegn07KlgzqqrAoGBAL3RX85r6WSl2K2zF+p6\n6gnTxMN+sMYA2AlXcTTA/uVm4Af8sWsNRZ9xaRxVuWdERFcT6+7RykwdEQX3EyaY\nfbw6efID3ahHeZCsAc8Sf2ChADZyb4Sw48e78aj+fm7X/8zSydJTRzHj3gFtjnbI\n/fbmEJ/wgt68mpOHzDn+3fejAoGBALHVAfhkgQ/dOys0p12PXC1XuJ7vU9HN8snB\nK1Ha19RE691W1GP3GRLFOTjP7UkDmvea3nlX8W6tqtLs18mJWPjL/834JFD8923LKKJDSLLKJ23-312LKAnvlAoGAWk4U51dYQzggSY9VJMXuEIUE30avKMS2aataeNwiSXWrF875iY61\nYoHBzRlFU05zu172Lt3ebB+piYU8fxC14PW7rJ/s+oBH6JkBkjjSbShfISqr+m/z\n++OlJe/YWHuh440ar9pnF2XhqbQWklNmSMotI+B8VTbi5id0EDxK+pg=\n-----END PRIVATE KEY-----\n",

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
			result, err := rsa.FromPEMPrivateKey([]byte(tc.privateKey))

			if tc.expectError {
				assert.NotNil(t, err)
			}

			if tc.expectEqual {
				pemPrivateKey, err := rsa.ToPEMPrivateKey(result)

				if err != nil {
					assert.Fail(t, "error expected to be nil")
				}

				assert.Equal(t, 0, strings.Compare(tc.privateKey, string(pemPrivateKey)))
			}
		})
	}
}

func TestRSAFromPEMPublicKey(t *testing.T) {
	rsa := NewRSA()

	testcases := []struct {
		name string

		publicKey string

		expectEqual bool
		expectError bool
	}{
		{
			name: "Valid Public Key",

			publicKey: "-----BEGIN PUBLIC KEY-----\nMIIBCgKCAQEArmawqPuI0wEtM0/CPWdCaAej+vwqog3qtdEnetw7WDQ6/cGdkPSX\n3ZegFUY2cd9egUW8fsLrWlpEsk7efrppKwpvpKC7/zsFy9kJueeWAI3rHdlmAxJO\nTqHCsMKLz4qoer0UNFs5jyiY3UOMFqauCTgeRQvpvTjoa7Lc4BgxtwJqL9iKzBMl\nk74MWsVYSCX5z44FIQVm0ebc5MoGVA6y2AJJiuetAWy4H/pl+fNh4C9zl1mFdKvV\nkLdw0nmlvSKkCPnGcTVlouw/UTngrsLFggv/pOhVHRZe+xgpdIhYLYJlcxzW2aNq\ndz/6C9R9qXaPPCtIyDIdxvdIt+CPX+QdRwIDAQAB\n-----END PUBLIC KEY-----\n",

			expectEqual: true,
			expectError: false,
		},
		{
			name: "InValid Public Key: Header Not Right",

			publicKey: "-----d5s6f6 2222 KEY-----\nMIIBCgKCAQEArmawqPuIdddddd0wEtM0/CPWdCaAej+vwqog3qtdEnetw7WDQ6/cGdkPSX\n3ZegFUY2cd9egUW8fsLrWlpEsk7efrppKwpvpKC7/zsFy9kJueeWAI3rHdlmAxJO\nTqHCsMKLz4qoer0UNFs5jyiY3UOMFqauCTgeRQvpvTjoa7Lc4BgxtwJqL9iKzBMl\nk74MWsVYSCX5z44FIQVm0ebc5MoGVA6y2AJJiuetAWy4H/pl+fNh4C9zl1mFdKvV\nkLdw0nmlvSKkCPnGcTVlouw/UTngrsLFggv/pOhVHRZe+xgpdIhYLYJlcxzW2aNq\ndz/6C9R9qXaPPCtIyDIdxvdIt+CPX+QdRwIDAQAB\n-----END PUBLIC KEY-----\n",

			expectEqual: false,
			expectError: true,
		},
		{
			name: "InValid Public Key: Footer Not Right",

			publicKey: "-----BEGIN PUBLIC KEY-----\nMIIBCgKCAQEArmawqPuI0wEtM0/CPWdCaAej+vwqog3qtdEnetw7WDQ6/cGdkPSX\n3ZegFUY2cd9egUW8fsLrWlpEsk7efrppKwpvpKC7/zsFy9kJueeWAI3rHdlmAxJO\nTqHCsMKLz4qoer0UNFs5jyiY3UOMFqauCTgeRQvpvTjoa7Lc4BgxtwJqL9iKzBMl\nk74MWsVYSCX5z44FIQVm0ebc5MoGVA6y2AJJiuetAWy4H/pl+fNh4C9zl1mFdKvV\nkLdw0nmlvSKkCPnGcTVlouw/UTngrsLFggv/pOhVHRZe+xgpdIhYLYJlcxzW2aNq\ndz/6C9R9qXaPPCtIyDIdxvdIt+CPX+QdRwIDAQAB\n-----e234dsf-----\n",

			expectEqual: false,
			expectError: true,
		},
		{
			name: "InValid Public Key: Body Not Right",

			publicKey: "-----BEGIN PUBLIC KEY-----\nMIIBCgKCAQEArmawqPuI0wEtM0/CPWdCaAej+vwqog3qtdEnetw7WDQ6/cGdkPSX\n3ZegFUY2cd9egUW8fsLrWlpEsk7efrppKwpvpKC7/zsFy9kJueeWAI3rHdlmAxJO\nTqHCsMKLz4qoer0UNFs5jyiY3UOMFqauCTgeRQvpvTjoa7Lc4BgxtwJqL9iKzBMl\nk74MWsVYSCX5z44FIQVm0ebc5MoGVA6y2AJJiuetAWy4H/i903oiplkmsgkl;we-2-o34klmdsl;kf\n-----END PUBLIC KEY-----\n",

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
			result, err := rsa.FromPEMPublicKey([]byte(tc.publicKey))
			if tc.expectError {
				assert.NotNil(t, err, err.Error())
			}

			if tc.expectEqual {
				pemPublicKey, err := rsa.ToPEMPublicKey(result)

				if err != nil {
					assert.Fail(t, "error expected to be nil")
				}

				assert.Equal(t, 0, strings.Compare(tc.publicKey, string(pemPublicKey)))
			}
		})
	}
}

func TestRSAToPEMPrivateKey(t *testing.T) {
	rsa := NewRSA()

	r2048, _ := rsa.R2048PrivateKey()
	r4096, _ := rsa.R4096PrivateKey()

	testcases := []struct {
		name string
		key  *crsa.PrivateKey

		isValid bool
	}{
		{
			name: "Valid R2048",
			key:  r2048,

			isValid: true,
		},
		{
			name: "Valid R4096",
			key:  r4096,

			isValid: true,
		},
		{
			name: "Invalid Nil",
			key:  nil,

			isValid: false,
		},
		{
			name: "Invalid empty",
			key:  &crsa.PrivateKey{},

			isValid: false,
		},
		{
			name: "Invalid empty N",
			key:  &crsa.PrivateKey{D: big.NewInt(10)},

			isValid: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			pemKey, err := rsa.ToPEMPrivateKey(tc.key)

			if tc.isValid {
				assert.Nil(t, err)
				testKey, err := rsa.FromPEMPrivateKey(pemKey)
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

func TestRSAToPEMPublicKey(t *testing.T) {
	rsa := NewRSA()

	_, r2048, _ := rsa.R2048()
	_, r4096, _ := rsa.R4096()

	testcases := []struct {
		name string
		key  *crsa.PublicKey

		isValid bool
	}{
		{
			name: "Valid R2048",
			key:  r2048,

			isValid: true,
		},
		{
			name: "Valid R4096",
			key:  r4096,

			isValid: true,
		},
		{
			name: "Invalid Nil",
			key:  nil,

			isValid: false,
		},
		{
			name: "Invalid N nil",
			key:  &crsa.PublicKey{},

			isValid: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			pemKey, err := rsa.ToPEMPublicKey(tc.key)

			if tc.isValid {
				assert.Nil(t, err)
				testKey, err := rsa.FromPEMPublicKey(pemKey)
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

func TestRSAGenerateKeys(t *testing.T) {
	rsa := &RSA{}

	testcases := []struct {
		name   string
		method func() (*crsa.PrivateKey, error)

		isError bool
	}{
		{
			name:   "Valid R2048",
			method: rsa.R2048PrivateKey,

			isError: false,
		},

		{
			name:   "Valid R4096",
			method: rsa.R4096PrivateKey,

			isError: false,
		},

		{
			name:   "Invalid method",
			method: func() (*crsa.PrivateKey, error) { return nil, errors.New("mock_fail") },

			isError: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			prvKey, pubKey, err := rsa.generateKeys(tc.method)

			if tc.isError {
				assert.Nil(t, prvKey)
				assert.Nil(t, pubKey)
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)

				prvPEM, err := rsa.ToPEMPrivateKey(prvKey)
				assert.Nil(t, err)
				assert.NotNil(t, prvPEM)
				assert.NotEmpty(t, prvPEM)

				pubPEM, err := rsa.ToPEMPublicKey(pubKey)
				assert.Nil(t, err)
				assert.NotNil(t, pubPEM)
				assert.NotEmpty(t, pubPEM)

				prvKey2, err := rsa.FromPEMPrivateKey(prvPEM)
				assert.Nil(t, err)
				assert.NotNil(t, prvKey2)

				pubKey2, err := rsa.FromPEMPublicKey(pubPEM)
				assert.Nil(t, err)
				assert.NotNil(t, pubKey2)
			}
		})
	}
}

func TestRSAR(t *testing.T) {
	rsa := &RSA{}

	testcases := []struct {
		name   string
		method func() (*crsa.PrivateKey, *crsa.PublicKey, error)

		isError bool
	}{
		{
			name:    "Valid R2048",
			method:  rsa.R2048,
			isError: false,
		},

		{
			name:    "Valid R4096",
			method:  rsa.R4096,
			isError: false,
		},

		{
			name:    "Invalid R",
			method:  func() (*crsa.PrivateKey, *crsa.PublicKey, error) { return nil, nil, errors.New("mock_error") },
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

				prvPEM, pubPEM, err := rsa.ToPEM(prvKey, pubKey)
				assert.Nil(t, err)
				assert.NotNil(t, prvPEM)
				assert.NotEmpty(t, prvPEM)
				assert.NotNil(t, pubPEM)
				assert.NotEmpty(t, pubPEM)

				prvKey2, pubKey2, err := rsa.FromPEM(prvPEM, pubPEM)
				assert.Nil(t, err)
				assert.NotNil(t, prvKey2)
				assert.NotNil(t, pubKey2)
			}
		})
	}
}

func TestRSARPEM(t *testing.T) {
	rsa := &RSA{}

	testcases := []struct {
		name   string
		method func() (*crsa.PrivateKey, p.PrivatePEM, *crsa.PublicKey, p.PublicPEM, error)

		isError bool
	}{
		{
			name:    "Valid R2048PEM",
			method:  rsa.R2048PEM,
			isError: false,
		},

		{
			name:    "Valid R4096PEM",
			method:  rsa.R4096PEM,
			isError: false,
		},

		{
			name: "Invalid R",
			method: func() (*crsa.PrivateKey, p.PrivatePEM, *crsa.PublicKey, p.PublicPEM, error) {
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

				prvKey2, pubKey2, err := rsa.FromPEM(prvPEM, pubPEM)
				assert.Nil(t, err)
				assert.NotNil(t, prvKey2)
				assert.NotNil(t, pubKey2)

				prvPEM2, pubPEM2, err := rsa.ToPEM(prvKey, pubKey)
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

func TestRSARPEMPrivateKey(t *testing.T) {
	rsa := &RSA{}

	testcases := []struct {
		name   string
		method func() (*crsa.PrivateKey, p.PrivatePEM, error)

		isError bool
	}{
		{
			name:    "Valid R2048PEMPrivateKey",
			method:  rsa.R2048PEMPrivateKey,
			isError: false,
		},

		{
			name:    "Valid R4096PEMPrivateKey",
			method:  rsa.R4096PEMPrivateKey,
			isError: false,
		},

		{
			name: "Invalid R",
			method: func() (*crsa.PrivateKey, p.PrivatePEM, error) {
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

				prvKey2, err := rsa.FromPEMPrivateKey(prvPEM)
				assert.Nil(t, err)
				assert.NotNil(t, prvKey2)

				prvPEM2, err := rsa.ToPEMPrivateKey(prvKey)
				assert.Nil(t, err)
				assert.NotNil(t, prvPEM2)
				assert.NotEmpty(t, prvPEM2)

				assert.Equal(t, 0, bytes.Compare(prvPEM, prvPEM2))
			}
		})
	}
}
