package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// SigningKey is one ES256 private key and its RFC 7638 thumbprint.
type SigningKey struct {
	KID     string
	private *ecdsa.PrivateKey
	x, y    string
}

// GenerateSigningKey creates a new P-256 key.
func GenerateSigningKey() (*SigningKey, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return newSigningKey(private)
}

// ParseSigningKey reads a PEM-encoded P-256 private key, in SEC 1 or PKCS #8 form.
func ParseSigningKey(data string) (*SigningKey, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, errors.New("signing key is not PEM")
	}
	if private, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return newSigningKey(private)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	private, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not an EC key")
	}
	return newSigningKey(private)
}

func newSigningKey(private *ecdsa.PrivateKey) (*SigningKey, error) {
	if private.Curve != elliptic.P256() {
		return nil, errors.New("signing key must use P-256")
	}
	point, err := private.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	// Uncompressed form: 0x04, then 32 bytes each of X and Y.
	x := base64.RawURLEncoding.EncodeToString(point[1:33])
	y := base64.RawURLEncoding.EncodeToString(point[33:65])
	thumbprint := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return &SigningKey{
		KID:     base64.RawURLEncoding.EncodeToString(thumbprint[:]),
		private: private,
		x:       x,
		y:       y,
	}, nil
}

// PEM returns the private key in SEC 1 PEM form.
func (k *SigningKey) PEM() (string, error) {
	der, err := x509.MarshalECPrivateKey(k.private)
	if err != nil {
		return "", fmt.Errorf("encode signing key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

// JWK is the public form of a signing key.
type JWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	KID string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS is the document served to token verifiers.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// KeySet holds the key that signs and the next key, which is published ahead
// of the switch so verifier caches already hold it.
type KeySet struct {
	current *SigningKey
	next    *SigningKey
}

// NewKeySet builds a key set. next may be nil.
func NewKeySet(current, next *SigningKey) *KeySet {
	return &KeySet{current: current, next: next}
}

// JWKS returns the public keys, current first.
func (s *KeySet) JWKS() JWKS {
	doc := JWKS{Keys: []JWK{s.current.jwk()}}
	if s.next != nil {
		doc.Keys = append(doc.Keys, s.next.jwk())
	}
	return doc
}

func (k *SigningKey) jwk() JWK {
	return JWK{KTY: "EC", CRV: "P-256", X: k.x, Y: k.y, KID: k.KID, Use: "sig", Alg: "ES256"}
}

// byKID finds a key by thumbprint.
func (s *KeySet) byKID(kid string) *SigningKey {
	if s.current.KID == kid {
		return s.current
	}
	if s.next != nil && s.next.KID == kid {
		return s.next
	}
	return nil
}
