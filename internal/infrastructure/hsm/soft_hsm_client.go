package hsm

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"platform-templates/templates/template-go-gin/internal/domain/exceptions"
	"platform-templates/templates/template-go-gin/internal/domain/ports/output"
	"platform-templates/templates/template-go-gin/internal/domain/valueobjects"

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

func NewSoftHSMClient(libraryPath, tokenLabel, pin string) (*SoftHSMClient, error) {
	ctx := pkcs11.New(libraryPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library")
	}

	err := ctx.Initialize()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return nil, fmt.Errorf("no slots found")
	}

	// Buscar el token por label
	var slotID uint
	for _, slot := range slots {
		tokenInfo, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if tokenInfo.Label == tokenLabel {
			slotID = slot
			break
		}
	}

	if slotID == 0 {
		return nil, fmt.Errorf("token with label %s not found", tokenLabel)
	}

	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}

	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		return nil, fmt.Errorf("failed to login: %w", err)
	}

	return &SoftHSMClient{
		ctx:        ctx,
		session:    session,
		tokenLabel: tokenLabel,
		pin:        pin,
	}, nil
}

func (c *SoftHSMClient) GenerateKeyPair(ctx context.Context, algorithm valueobjects.KeyAlgorithm, size int) (publicKey []byte, keyHandle string, err error) {
	var pubHandle, privHandle pkcs11.ObjectHandle

	switch algorithm {
	case valueobjects.RSA:
		pubHandle, privHandle, err = c.generateRSAKeyPair(size)
	case valueobjects.ECDSA:
		pubHandle, privHandle, err = c.generateECDSAKeyPair(size)
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

func (c *SoftHSMClient) generateRSAKeyPair(size int) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, size),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "RSA Key"),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "RSA Key"),
	}

	pubHandle, privHandle, err := c.ctx.GenerateKeyPair(c.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)

	return pubHandle, privHandle, err
}

func (c *SoftHSMClient) generateECDSAKeyPair(size int) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
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
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "ECDSA Key"),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "ECDSA Key"),
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

	// Implementación simplificada - en producción necesitarías procesar los atributos
	// según el tipo de clave (RSA vs ECDSA) y formatear adecuadamente
	for _, attr := range attrs {
		if attr.Type == pkcs11.CKA_MODULUS && len(attr.Value) > 0 {
			return attr.Value, nil
		}
		if attr.Type == pkcs11.CKA_EC_POINT && len(attr.Value) > 0 {
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

	// Usar mecanismo PKCS#1 para RSA
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

func (c *SoftHSMClient) GetPublicKey(ctx context.Context, keyHandle string) ([]byte, error) {
	// En este adaptador, no obtenemos la clave pública del HSM en cada solicitud
	// porque ya la exportamos al generar la clave y la almacenamos en la base de datos
	return nil, fmt.Errorf("not implemented: GetPublicKey from HSM handle")
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

func (c *SoftHSMClient) Close() error {
	if c.ctx != nil {
		c.ctx.Logout(c.session)
		c.ctx.CloseSession(c.session)
		c.ctx.Finalize()
		c.ctx.Destroy()
	}
	return nil
}
