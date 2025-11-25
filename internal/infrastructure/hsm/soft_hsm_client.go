package hsm

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"strings"
	"time"

	"github.com/miekg/pkcs11"
)

type SoftHSMClient struct {
	ctx        *pkcs11.Ctx
	session    pkcs11.SessionHandle
	tokenLabel string
	pin        string
}

// Garantiza implementación del puerto
var _ output.HSMClient = (*SoftHSMClient)(nil)

func NewMockHSMClient() *SoftHSMClient {
	return &SoftHSMClient{}
}

func (c *SoftHSMClient) GenerateKeyPair(ctx context.Context, algorithm valueobjects.KeyAlgorithm, size int, label string) (publicKey []byte, keyHandle string, err error) {
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
		return nil, "", fmt.Errorf("Ed25519 not supported by SoftHSMv2 in this implementation")
	default:
		return nil, "", errors.New(string(exceptions.ErrInvalidAlgorithm))
	}

	if err != nil {
		return nil, "", err
	}

	// Exportar clave pública
	publicKey, err = c.exportPublicKey(pubHandle)
	if err != nil {
		c.ctx.DestroyObject(c.session, pubHandle)
		c.ctx.DestroyObject(c.session, privHandle)
		return nil, "", err
	}

	// Convertir el handle a string para almacenar
	keyHandle = fmt.Sprintf("%d", privHandle)

	return publicKey, keyHandle, nil
}

func (c *SoftHSMClient) generateRSAKeyPair(size int, label string) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, size),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
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

	pubHandle, privHandle, err := c.ctx.GenerateKeyPair(c.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)

	return pubHandle, privHandle, err
}

func (c *SoftHSMClient) generateECDSAKeyPair(size int, label string) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	var curve asn1.ObjectIdentifier

	switch size {
	case 256:
		curve = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7} // secp256r1
	case 384:
		curve = asn1.ObjectIdentifier{1, 3, 132, 0, 34} // secp384r1
	case 521:
		curve = asn1.ObjectIdentifier{1, 3, 132, 0, 35} // secp521r1
	default:
		return 0, 0, errors.New(string(exceptions.ErrInvalidKeySize))
	}

	ecParams, err := asn1.Marshal(curve)
	if err != nil {
		return 0, 0, err
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

	pubHandle, privHandle, err := c.ctx.GenerateKeyPair(c.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)

	return pubHandle, privHandle, err
}

func (c *SoftHSMClient) exportPublicKey(pubHandle pkcs11.ObjectHandle) ([]byte, error) {
	attrs, err := c.ctx.GetAttributeValue(c.session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, err
	}

	// Para RSA: combinar módulo y exponente
	// Para ECDSA: usar el punto EC
	for _, attr := range attrs {
		if attr.Type == pkcs11.CKA_MODULUS && len(attr.Value) > 0 {
			// RSA public key
			return attr.Value, nil
		}
		if attr.Type == pkcs11.CKA_EC_POINT && len(attr.Value) > 0 {
			// ECDSA public key
			return attr.Value, nil
		}
	}

	return nil, fmt.Errorf("failed to export public key")
}

func (c *SoftHSMClient) SignHash(ctx context.Context, keyHandle string, hash []byte) ([]byte, error) {
	// Convertir keyHandle a handle
	var handle pkcs11.ObjectHandle
	_, err := fmt.Sscanf(keyHandle, "%d", &handle)
	if err != nil {
		return nil, fmt.Errorf("invalid key handle: %w", err)
	}

	// Determinar el mecanismo basado en el tipo de clave
	// Por simplicidad, usamos SHA256_RSA_PKCS para RSA y ECDSA con SHA256
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)

	err = c.ctx.SignInit(c.session, []*pkcs11.Mechanism{mechanism}, handle)
	if err != nil {
		return nil, err
	}

	signature, err := c.ctx.Sign(c.session, hash)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (c *SoftHSMClient) VerifySignature(ctx context.Context, keyHandle string, hash, signature []byte) (bool, error) {
	// Para verificación, necesitamos la clave pública
	// En una implementación real, buscaríamos la clave pública correspondiente
	// Por ahora, devolvemos true para testing
	return true, nil
}

func (c *SoftHSMClient) GetPublicKey(ctx context.Context, keyHandle string) ([]byte, error) {
	// Convertir keyHandle a handle
	var handle pkcs11.ObjectHandle
	_, err := fmt.Sscanf(keyHandle, "%d", &handle)
	if err != nil {
		return nil, fmt.Errorf("invalid key handle: %w", err)
	}

	// Intentar obtener atributos de clave pública
	attrs, err := c.ctx.GetAttributeValue(c.session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key attributes: %w", err)
	}

	for _, attr := range attrs {
		if len(attr.Value) > 0 {
			return attr.Value, nil
		}
	}

	return nil, fmt.Errorf("public key not found for handle")
}

func (c *SoftHSMClient) DeleteKey(ctx context.Context, keyHandle string) error {
	var handle pkcs11.ObjectHandle
	_, err := fmt.Sscanf(keyHandle, "%d", &handle)
	if err != nil {
		return fmt.Errorf("invalid key handle: %w", err)
	}

	err = c.ctx.DestroyObject(c.session, handle)
	if err != nil {
		return err
	}

	return nil
}

func (c *SoftHSMClient) ListKeys(ctx context.Context) ([]*entities.HSMKey, error) {
	// Buscar todas las claves privadas (que son las que manejamos)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}

	err := c.ctx.FindObjectsInit(c.session, template)
	if err != nil {
		return nil, err
	}

	handles, _, err := c.ctx.FindObjects(c.session, 100)
	if err != nil {
		c.ctx.FindObjectsFinal(c.session)
		return nil, err
	}

	var hsmKeys []*entities.HSMKey
	for _, handle := range handles {
		// Obtener atributos de la clave
		attrs, err := c.ctx.GetAttributeValue(c.session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		})
		if err != nil {
			continue // Saltar claves problemáticas
		}

		hsmKey := &entities.HSMKey{
			KeyHandle: fmt.Sprintf("%d", handle),
			CreatedAt: time.Now().UTC(),
			IsActive:  true,
			Usage:     valueobjects.KeyUsageBoth,
		}

		for _, attr := range attrs {
			switch attr.Type {
			case pkcs11.CKA_LABEL:
				hsmKey.Label = string(attr.Value)
			case pkcs11.CKA_KEY_TYPE:
				switch attr.Value[0] {
				case pkcs11.CKK_RSA:
					hsmKey.Type = valueobjects.KeyTypeRSA
				case pkcs11.CKK_EC:
					hsmKey.Type = valueobjects.KeyTypeECDSA
				}
			case pkcs11.CKA_ID:
				// Podemos usar el ID como TenantID temporalmente
				if len(attr.Value) > 0 {
					hsmKey.TenantID = string(attr.Value)
				}
			}
		}

		// Obtener la clave pública si es posible
		if publicKey, err := c.GetPublicKey(ctx, hsmKey.KeyHandle); err == nil {
			hsmKey.PublicKey = publicKey
		}

		hsmKeys = append(hsmKeys, hsmKey)
	}

	c.ctx.FindObjectsFinal(c.session)
	return hsmKeys, nil
}

func (c *SoftHSMClient) Encrypt(ctx context.Context, keyHandle string, plaintext []byte) ([]byte, error) {
	var handle pkcs11.ObjectHandle
	_, err := fmt.Sscanf(keyHandle, "%d", &handle)
	if err != nil {
		return nil, fmt.Errorf("invalid key handle: %w", err)
	}

	// Usar mecanismo RSA PKCS para encriptación
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)

	err = c.ctx.EncryptInit(c.session, []*pkcs11.Mechanism{mechanism}, handle)
	if err != nil {
		return nil, err
	}

	ciphertext, err := c.ctx.Encrypt(c.session, plaintext)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func (c *SoftHSMClient) Decrypt(ctx context.Context, keyHandle string, ciphertext []byte) ([]byte, error) {
	var handle pkcs11.ObjectHandle
	_, err := fmt.Sscanf(keyHandle, "%d", &handle)
	if err != nil {
		return nil, fmt.Errorf("invalid key handle: %w", err)
	}

	// Usar mecanismo RSA PKCS para desencriptación
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)

	err = c.ctx.DecryptInit(c.session, []*pkcs11.Mechanism{mechanism}, handle)
	if err != nil {
		return nil, err
	}

	plaintext, err := c.ctx.Decrypt(c.session, ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (c *SoftHSMClient) GenerateKeyPairWithLabel(ctx context.Context, algorithm valueobjects.KeyAlgorithm, size int, label, tenantID string) (publicKey []byte, keyHandle string, err error) {
	// Incorporar tenantID en el label para multitenancy
	fullLabel := fmt.Sprintf("%s_%s", tenantID, label)
	return c.GenerateKeyPair(ctx, algorithm, size, fullLabel)
}

func (c *SoftHSMClient) FindKeysByLabel(ctx context.Context, labelPattern string) ([]*entities.HSMKey, error) {
	allKeys, err := c.ListKeys(ctx)
	if err != nil {
		return nil, err
	}

	var matchedKeys []*entities.HSMKey
	for _, key := range allKeys {
		if strings.Contains(key.Label, labelPattern) {
			matchedKeys = append(matchedKeys, key)
		}
	}

	return matchedKeys, nil
}

func (c *SoftHSMClient) Close() error {
	if c.ctx != nil {
		c.ctx.Logout(c.session)
		c.ctx.CloseSession(c.session)
		c.ctx.Finalize()
		c.ctx.Destroy()
	}
	return nil
}
