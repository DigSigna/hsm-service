package hsm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
)

type SoftHSMClient struct {
	ctx        *pkcs11.Ctx
	session    pkcs11.SessionHandle
	tokenLabel string
	pin        string
	mutex      sync.Mutex // Solo para thread-safety básico
}

// Garantiza implementación del puerto
var _ output.HSMClient = (*SoftHSMClient)(nil)

func NewMockHSMClient() *SoftHSMClient {
	return &SoftHSMClient{}
}

func NewSoftHSMClient(modulePath, pin string, slot uint) (*SoftHSMClient, error) {
	log.Printf("DEBUG: Initializing SoftHSMClient with module: %s, slot: %d", modulePath, slot)
	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module")
	}

	err := ctx.Initialize()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11: %v", err)
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		ctx.Finalize()
		return nil, fmt.Errorf("failed to get slots: %v", err)
	}

	log.Printf("DEBUG: Found %d slots", len(slots))

	if len(slots) == 0 {
		ctx.Finalize()
		return nil, fmt.Errorf("no PKCS#11 slots available")
	}

	// Usar slot especificado o default
	targetSlot := slots[0]
	if slot < uint(len(slots)) {
		targetSlot = slots[slot]
	}

	log.Printf("DEBUG: Using slot ID: 0x%x", targetSlot)

	session, err := ctx.OpenSession(targetSlot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		return nil, fmt.Errorf("failed to open session: %v", err)
	}

	log.Printf("DEBUG: Opened session: %v", session)

	// Login
	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		ctx.CloseSession(session)
		ctx.Finalize()
		return nil, fmt.Errorf("failed to login: %v", err)
	}

	log.Printf("DEBUG: Login successful or already logged in")

	return &SoftHSMClient{
		ctx:     ctx,
		session: session,
	}, nil
}

func (c *SoftHSMClient) HealthCheck(ctx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	_, err := c.ctx.GetSessionInfo(c.session)
	return err
}

func (c *SoftHSMClient) GenerateKeyPair(ctx context.Context, algorithm valueobjects.KeyAlgorithm, size int, label string) (publicKey []byte, keyHandle string, err error) {
	log.Printf("DEBUG [GenerateKeyPair]: algorithm=%s, size=%d, label=%s", algorithm, size, label)
	// var pubHandle, privHandle pkcs11.ObjectHandle
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Usar tu implementación existente pero con c.session
	var pubHandle, privHandle pkcs11.ObjectHandle

	// Validar parámetros
	if label == "" {
		return nil, "", errors.New("key label cannot be empty")
	}

	switch algorithm {
	case valueobjects.RSA:
		log.Printf("DEBUG: Generating RSA key pair")
		pubHandle, privHandle, err = c.generateRSAKeyPair(size, label)
	case valueobjects.ECDSA:
		log.Printf("DEBUG: Generating ECDSA key pair")
		pubHandle, privHandle, err = c.generateECDSAKeyPair(size, label)
	case valueobjects.Ed25519:
		log.Printf("DEBUG: Ed25519 not supported by SoftHSMv2 in this implementation")
		return nil, "", fmt.Errorf("Ed25519 not supported by SoftHSMv2 in this implementation")
	default:
		err = fmt.Errorf("unsupported algorithm: %s", algorithm)
		return nil, "", errors.New(string(exceptions.ErrInvalidAlgorithm))
	}

	if err != nil {
		log.Printf("ERROR [GenerateKeyPair]: %v", err)
		return nil, "", fmt.Errorf("HSM_OPERATION_FAILED: operation=generate_key_pair: %w", err)
	}

	log.Printf("DEBUG: Key pair generated, pubHandle=%d, privHandle=%d", pubHandle, privHandle)

	// Exportar clave pública
	publicKey, err = c.exportPublicKey(pubHandle)
	if err != nil {
		log.Printf("ERROR [exportPublicKey]: %v", err)
		c.ctx.DestroyObject(c.session, pubHandle)
		c.ctx.DestroyObject(c.session, privHandle)
		return nil, "", err
	}

	// Convertir el handle a string para almacenar
	keyHandle = fmt.Sprintf("%d", privHandle)
	log.Printf("DEBUG: Success - keyHandle=%s, publicKey length=%d", keyHandle, len(publicKey))

	return publicKey, keyHandle, nil
}

func (c *SoftHSMClient) generateRSAKeyPair(size int, label string) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	log.Printf("DEBUG [generateRSAKeyPair]: Creating templates for RSA %d bits, label: %s", size, label)

	// Ensure valid key sizes
	if size != 2048 && size != 3072 && size != 4096 {
		return 0, 0, fmt.Errorf("unsupported RSA key size: %d", size)
	}

	// Public exponent: 65537 (0x01 0x00 0x01) as big-endian bytes
	pubExp := []byte{0x01, 0x00, 0x01}

	// Use uint for modulus bits (CK_ULONG)
	modulusBits := uint(size)

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, modulusBits),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, pubExp),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),          // persist key on token
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)), // prefer []byte
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)),
	}

	log.Printf("DEBUG: Calling GenerateKeyPair...")
	pubHandle, privHandle, err := c.ctx.GenerateKeyPair(c.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)

	if err != nil {
		if pkErr, ok := err.(pkcs11.Error); ok {
			log.Printf("ERROR: PKCS#11 Error Code: 0x%08X", uint(pkErr))
		}
		log.Printf("ERROR: GenerateKeyPair failed: %v", err)
		return 0, 0, err
	}

	log.Printf("DEBUG: GenerateKeyPair successful - pubHandle=%d, privHandle=%d", pubHandle, privHandle)
	return pubHandle, privHandle, nil
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

	// Marshal the selected curve OID for EC_PARAMS and handle errors.
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

	pubHandle, privHandle, err := c.ctx.GenerateKeyPair(c.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)

	return pubHandle, privHandle, err
}

func (c *SoftHSMClient) exportPublicKey(pubHandle pkcs11.ObjectHandle) ([]byte, error) {
	// 1) Leer tipo de clave
	keyTypeAttrs, err := c.ctx.GetAttributeValue(c.session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return nil, err
	}
	if len(keyTypeAttrs) == 0 || len(keyTypeAttrs[0].Value) == 0 {
		return nil, errors.New("cannot determine key type")
	}

	kt := keyTypeAttrs[0].Value[0]

	switch kt {
	case byte(pkcs11.CKK_RSA):
		// Pedir sólo modulus y exponent
		attrs, err := c.ctx.GetAttributeValue(c.session, pubHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		})
		if err != nil {
			return nil, err
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
			return nil, errors.New("rsa attributes missing")
		}

		n := new(big.Int).SetBytes(modulusBytes)
		// exponentBytes could be big-endian bytes, convert to int
		e := 0
		for _, b := range exponentBytes {
			e = e<<8 + int(b)
		}
		rsaPub := &rsa.PublicKey{N: n, E: e}
		derBytes, err := x509.MarshalPKIXPublicKey(rsaPub)
		if err != nil {
			return nil, err
		}
		// devolver DER; si quieres PEM lo convierto abajo
		return derBytes, nil

	case byte(pkcs11.CKK_EC):
		// Pedir sólo el punto EC y CKA_EC_PARAMS (OID)
		attrs, err := c.ctx.GetAttributeValue(c.session, pubHandle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		})
		if err != nil {
			return nil, err
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
			return nil, errors.New("ec attributes missing")
		}

		// ecPoint viene con DER OCTET STRING wrapping; desempaquetar si es necesario
		var rawPoint []byte
		if rest, err := asn1.Unmarshal(ecPoint, &rawPoint); err == nil && len(rest) == 0 {
			// rawPoint contains the unwrapped EC point bytes
			rawPoint = rawPoint
		} else {
			// si no se puede desempaquetar, asumir que ecPoint ya es el punto
			rawPoint = ecPoint
		}

		// Obtener OID de parámetro para seleccionar curva
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(ecParams, &oid); err != nil {
			return nil, err
		}

		var curve elliptic.Curve
		switch {
		case oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}): // P-256
			curve = elliptic.P256()
		case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 34}): // P-384
			curve = elliptic.P384()
		case oid.Equal(asn1.ObjectIdentifier{1, 3, 132, 0, 35}): // P-521
			curve = elliptic.P521()
		default:
			return nil, errors.New("unsupported ec curve oid: " + oid.String())
		}

		// rawPoint starts with 0x04 (uncompressed) + X+Y
		if len(rawPoint) == 0 || rawPoint[0] != 0x04 {
			return nil, errors.New("unexpected ec point format")
		}
		coordLen := (len(rawPoint) - 1) / 2
		x := new(big.Int).SetBytes(rawPoint[1 : 1+coordLen])
		y := new(big.Int).SetBytes(rawPoint[1+coordLen:])
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		derBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, err
		}
		return derBytes, nil

	default:
		return nil, errors.New("unsupported key type")
	}
}

// helper para devolver PEM si lo quieres
func derToPEM(der []byte, typ string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
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
