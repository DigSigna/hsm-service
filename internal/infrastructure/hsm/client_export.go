package hsm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
)

// exportPublicKey exports a public key from the HSM
func (c *SoftHSMClient) exportPublicKey(pubHandle pkcs11.ObjectHandle) ([]byte, error) {
	keyTypeAttrs, err := c.ctx.GetAttributeValue(c.session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get key type: %w", err)
	}

	if len(keyTypeAttrs) == 0 || len(keyTypeAttrs[0].Value) == 0 {
		return nil, errors.New("cannot determine key type")
	}

	switch keyTypeAttrs[0].Value[0] {
	case byte(pkcs11.CKK_RSA):
		return c.exportRSAPublicKey(pubHandle)
	case byte(pkcs11.CKK_EC):
		return c.exportECPublicKey(pubHandle)
	default:
		return nil, errors.New("unsupported key type")
	}
}

// exportRSAPublicKey exports an RSA public key
func (c *SoftHSMClient) exportRSAPublicKey(pubHandle pkcs11.ObjectHandle) ([]byte, error) {
	attrs, err := c.ctx.GetAttributeValue(c.session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get RSA attributes: %w", err)
	}

	var modulusBytes, exponentBytes []byte
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_MODULUS:
			modulusBytes = a.Value
		case pkcs11.CKA_PUBLIC_EXPONENT:
			exponentBytes = a.Value
		}
	}

	if len(modulusBytes) == 0 || len(exponentBytes) == 0 {
		return nil, errors.New("RSA attributes missing")
	}

	n := new(big.Int).SetBytes(modulusBytes)
	e := int(new(big.Int).SetBytes(exponentBytes).Int64())

	rsaPub := &rsa.PublicKey{N: n, E: e}
	return x509.MarshalPKIXPublicKey(rsaPub)
}

// exportECPublicKey exports an EC public key
func (c *SoftHSMClient) exportECPublicKey(pubHandle pkcs11.ObjectHandle) ([]byte, error) {
	attrs, err := c.ctx.GetAttributeValue(c.session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get EC attributes: %w", err)
	}

	var ecPoint, ecParams []byte
	for _, a := range attrs {
		switch a.Type {
		case pkcs11.CKA_EC_POINT:
			ecPoint = a.Value
		case pkcs11.CKA_EC_PARAMS:
			ecParams = a.Value
		}
	}

	if len(ecPoint) == 0 || len(ecParams) == 0 {
		return nil, errors.New("EC attributes missing")
	}

	// Unwrap EC point if needed
	rawPoint := ecPoint
	if rest, err := asn1.Unmarshal(ecPoint, &rawPoint); err == nil && len(rest) == 0 {
		// Successfully unwrapped
	} else {
		rawPoint = ecPoint
	}

	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(ecParams, &oid); err != nil {
		return nil, fmt.Errorf("failed to unmarshal EC params: %w", err)
	}

	var curve elliptic.Curve
	switch {
	case oid.Equal(p256OID):
		curve = elliptic.P256()
	case oid.Equal(p384OID):
		curve = elliptic.P384()
	case oid.Equal(p521OID):
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve OID: %s", oid)
	}

	if len(rawPoint) == 0 || rawPoint[0] != 0x04 {
		return nil, errors.New("unexpected EC point format")
	}

	coordLen := (len(rawPoint) - 1) / 2
	x := new(big.Int).SetBytes(rawPoint[1 : 1+coordLen])
	y := new(big.Int).SetBytes(rawPoint[1+coordLen:])

	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	return x509.MarshalPKIXPublicKey(pub)
}
