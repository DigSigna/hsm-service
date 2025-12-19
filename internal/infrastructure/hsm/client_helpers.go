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
