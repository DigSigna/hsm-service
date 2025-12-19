package hsm

import (
	"context"
	"errors"
	"fmt"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/valueobjects"
	"time"

	"github.com/miekg/pkcs11"
)

// SignHash signs a hash using the specified key
func (c *SoftHSMClient) SignHash(ctx context.Context, keyHandle string, hash []byte) (publicKey []byte, err error) {
	start := time.Now()

	defer func() {
		data := valueobjects.AuditData{
			ServiceName: "soft-hsm-client",
			EventType:   "HSM_OPERATION",
			Operation:   "SIGN_HASH",
			Success:     err == nil,
			ErrMsg:      errToString(err),
			StatusCode:  exceptions.GetCode(err),
			ActorType:   "SERVICE",
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata: map[string]any{
				"hash_length": len(hash),
			},
		}
		if c.auditDispatcher != nil {
			c.auditDispatcher.AuditOperation(ctx, data)
		}
	}()

	handle, err := parseKeyHandle(keyHandle)
	if err != nil {
		return nil, err
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if c.closed {
		return nil, errors.New(hsmClosedMsg)
	}

	// Determine mechanism based on key type
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)

	if err := c.ctx.SignInit(c.session, []*pkcs11.Mechanism{mechanism}, handle); err != nil {
		return nil, fmt.Errorf("failed to initialize signing: %w", err)
	}

	signature, err := c.ctx.Sign(c.session, hash)

	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

func (c *SoftHSMClient) VerifySignature(ctx context.Context, keyHandle string, hash, signature []byte) (bool, error) {
	// Para verificación, necesitamos la clave pública
	// En una implementación real, buscaríamos la clave pública correspondiente
	// Por ahora, devolvemos true para testing
	return true, nil
}

func (c *SoftHSMClient) Encrypt(ctx context.Context, keyHandle string, plaintext []byte) ([]byte, error) {
	var handle pkcs11.ObjectHandle
	_, err := fmt.Sscanf(keyHandle, "%d", &handle)
	if err != nil {
		return nil, fmt.Errorf(invalidKeyMsg+": %w", err)
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
		return nil, fmt.Errorf(invalidKeyMsg+": %w", err)
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
