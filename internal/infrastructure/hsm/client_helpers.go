package hsm

import (
	"encoding/asn1"
	"fmt"
	"hsm-service/internal/domain/valueobjects"
	"strconv"

	"github.com/miekg/pkcs11"
)

const (
	objectBatchSize = 100
)

var (
	// Pre-allocated elliptic curve OIDs
	p256OID = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	p384OID = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	p521OID = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	hsmClosedMsg  = "HSM client is closed"
	invalidKeyMsg = "invalid key handle"
)

// errToString safely converts error to string
func errToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// parseKeyHandle parses a string key handle
func parseKeyHandle(keyHandle string) (pkcs11.ObjectHandle, error) {
	handle, err := strconv.ParseUint(keyHandle, 10, 64)
	if err != nil {
		return 0, fmt.Errorf(invalidKeyMsg+": %w", err)
	}
	return pkcs11.ObjectHandle(handle), nil
}

// findPrivateKeyByLabel searches for a private key by its CKA_LABEL attribute
// This is the correct way to retrieve keys persistently in PKCS#11
// since handles are session-specific and ephemeral.
func (c *SoftHSMClient) findPrivateKeyByLabel(label string) (pkcs11.ObjectHandle, error) {
	// Define search template for private key with specific label
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	// Initialize search
	if err := c.ctx.FindObjectsInit(c.session, template); err != nil {
		return 0, fmt.Errorf("failed to initialize object search: %w", err)
	}
	defer c.ctx.FindObjectsFinal(c.session)

	// Find objects (should return exactly one)
	objects, _, err := c.ctx.FindObjects(c.session, 1)
	if err != nil {
		return 0, fmt.Errorf("failed to find objects: %w", err)
	}

	if len(objects) == 0 {
		return 0, fmt.Errorf("private key with label '%s' not found in HSM", label)
	}

	return objects[0], nil
}

// findPublicKeyByLabel searches for a public key by its CKA_LABEL attribute
func (c *SoftHSMClient) findPublicKeyByLabel(label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	if err := c.ctx.FindObjectsInit(c.session, template); err != nil {
		return 0, fmt.Errorf("failed to initialize object search: %w", err)
	}
	defer c.ctx.FindObjectsFinal(c.session)

	objects, _, err := c.ctx.FindObjects(c.session, 1)
	if err != nil {
		return 0, fmt.Errorf("failed to find objects: %w", err)
	}

	if len(objects) == 0 {
		return 0, fmt.Errorf("public key with label '%s' not found in HSM", label)
	}

	return objects[0], nil
}

// mapKeyType maps PKCS#11 key types to domain key types
func mapKeyType(pkcs11Type byte) valueobjects.KeyType {
	switch pkcs11Type {
	case pkcs11.CKK_RSA:
		return valueobjects.KeyTypeRSA
	case pkcs11.CKK_EC:
		return valueobjects.KeyTypeECDSA
	default:
		return valueobjects.KeyTypeUnknown
	}
}
