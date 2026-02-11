package hsm

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/valueobjects"
	"time"

	"github.com/miekg/pkcs11"
)

func (c *SoftHSMClient) GenerateKeyPair(ctx context.Context, algorithm valueobjects.KeyAlgorithm, size int, label string) (publicKey []byte, keyHandle string, err error) {
	start := time.Now()

	defer func() {
		data := valueobjects.AuditData{
			ServiceName: "soft-hsm-client",
			EventType:   "HSM_OPERATION",
			Operation:   "GENERATE_KEY_PAIR",
			Success:     err == nil,
			ErrMsg:      errToString(err),
			StatusCode:  exceptions.GetCode(err),
			ActorType:   "SERVICE",
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata: map[string]interface{}{
				"duration_ms":       time.Since(start).Milliseconds(),
				"public_key_length": len(publicKey),
				"algorithm":         algorithm.String(),
				"key_size":          size,
				"label":             label,
			},
		}
		if c.auditDispatcher != nil {
			c.auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()

	if label == "" {
		err = errors.New("key label cannot be empty")
		return nil, "", err
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		err = errors.New(hsmClosedMsg)
		return nil, "", err
	}

	var pubHandle, privHandle pkcs11.ObjectHandle

	// Validar parámetros
	if label == "" {
		return nil, "", errors.New("key label cannot be empty")
	}

	switch algorithm {
	case valueobjects.RSA:
		pubHandle, privHandle, err = c.generateRSAKeyPair(size, label)
	case valueobjects.ECDSA:
		pubHandle, privHandle, err = c.generateECDSAKeyPair(size, label)
	case valueobjects.Ed25519:
		err = errors.New("Ed25519 not supported by SoftHSMv2")
	default:
		err = exceptions.DomainErrInvalidAlgorithm
	}

	if err != nil {
		return nil, "", fmt.Errorf("HSM_OPERATION_FAILED: operation=generate_key_pair: %w", err)
	}

	// Export public key
	publicKey, err = c.exportPublicKey(pubHandle)
	if err != nil {
		c.ctx.DestroyObject(c.session, pubHandle)
		c.ctx.DestroyObject(c.session, privHandle)
		return nil, "", err
	}

	// Return the label as the key identifier (persistent across sessions)
	// NOT the handle (which is ephemeral and only valid in current session)
	keyHandle = label

	return publicKey, keyHandle, nil
}

// GenerateKeyPairWithLabel generates a key pair with tenant-specific label
func (c *SoftHSMClient) GenerateKeyPairWithLabel(ctx context.Context, algorithm valueobjects.KeyAlgorithm, size int, label, tenantID string) (publicKey []byte, keyHandle string, err error) {
	fullLabel := fmt.Sprintf("%s_%s", tenantID, label)
	return c.GenerateKeyPair(ctx, algorithm, size, fullLabel)
}

// generateRSAKeyPair generates an RSA key pair
func (c *SoftHSMClient) generateRSAKeyPair(size int, label string) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	// Validate key size
	if size != 2048 && size != 3072 && size != 4096 {
		return 0, 0, fmt.Errorf("unsupported RSA key size: %d", size)
	}

	pubExp := []byte{0x01, 0x00, 0x01} // 65537

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, uint(size)),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, pubExp),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	return c.ctx.GenerateKeyPair(c.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)
}

// generateECDSAKeyPair generates an ECDSA key pair
func (c *SoftHSMClient) generateECDSAKeyPair(size int, label string) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	var curve asn1.ObjectIdentifier

	switch size {
	case 256:
		curve = p256OID
	case 384:
		curve = p384OID
	case 521:
		curve = p521OID
	default:
		return 0, 0, exceptions.DomainErrInvalidKeySize
	}

	ecParams, err := asn1.Marshal(curve)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to marshal EC params: %w", err)
	}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	return c.ctx.GenerateKeyPair(c.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)
}
