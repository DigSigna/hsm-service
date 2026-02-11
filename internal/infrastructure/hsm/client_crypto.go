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

type contextKey string

const (
	tenantErrorMsg               = "error checking tenant existence"
	keyNotFoundErrMsg            = "failed to find key with label '%s': %w"
	tenantIDKey       contextKey = "tenant_id"
)

// SignHash signs a hash using the specified key
func (c *SoftHSMClient) SignHash(
	ctx context.Context,
	keyHandle string,
	hash []byte,
	identityContext *valueobjects.IdentityContext) (publicKey []byte, err error) {
	ctx = context.WithValue(ctx, tenantIDKey, identityContext.TenantID)
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
				"handle":      keyHandle,
				"hash_length": len(hash),
			},
		}
		if c.auditDispatcher != nil {
			c.auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()

	// Instead of parsing the keyHandle as a numeric handle (which is ephemeral),
	// treat it as a label and search for the key in the current session
	handle, err := c.findPrivateKeyByLabel(keyHandle)
	if err != nil {
		return nil, fmt.Errorf(keyNotFoundErrMsg, keyHandle, err)
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if c.closed {
		return nil, errors.New(hsmClosedMsg)
	}

	// Verify key exists and is accessible (optional check, findPrivateKeyByLabel already does this)
	_, err = c.ctx.GetAttributeValue(c.session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("key with label '%s' not accessible: %w", keyHandle, err)
	}

	// Determine mechanism based on key type
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)

	if err := c.ctx.SignInit(c.session, []*pkcs11.Mechanism{mechanism}, handle); err != nil {
		return nil, fmt.Errorf("failed to initialize signing operation: %w", err)
	}

	signature, err := c.ctx.Sign(c.session, hash)

	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

func (c *SoftHSMClient) VerifySignature(ctx context.Context, keyHandle string, hash, signature []byte) (isValid bool, err error) {
	start := time.Now()

	defer func() {
		data := valueobjects.AuditData{
			ServiceName: "soft-hsm-client",
			EventType:   "HSM_OPERATION",
			Operation:   "VERIFY_SIGNATURE",
			Success:     err == nil,
			ErrMsg:      errToString(err),
			StatusCode:  exceptions.GetCode(err),
			ActorType:   "SERVICE",
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata: map[string]any{
				"handle":           keyHandle,
				"hash_length":      len(hash),
				"signature_length": len(signature),
				"is_valid":         isValid,
			},
		}
		if c.auditDispatcher != nil {
			c.auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()

	// Find the public key by label (persistent identifier)
	handle, err := c.findPublicKeyByLabel(keyHandle)
	if err != nil {
		return false, fmt.Errorf(keyNotFoundErrMsg, keyHandle, err)
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if c.closed {
		return false, errors.New(hsmClosedMsg)
	}

	// Verify key exists and is accessible
	_, err = c.ctx.GetAttributeValue(c.session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
	})
	if err != nil {
		return false, fmt.Errorf("public key with label '%s' not accessible: %w", keyHandle, err)
	}

	// Determine mechanism based on key type (matching SignHash)
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)

	if err := c.ctx.VerifyInit(c.session, []*pkcs11.Mechanism{mechanism}, handle); err != nil {
		return false, fmt.Errorf("failed to initialize verification operation: %w", err)
	}

	err = c.ctx.Verify(c.session, hash, signature)
	if err != nil {
		// If verification fails, check if it's because signature is invalid
		// or because of an actual error
		pkcs11Err, ok := err.(pkcs11.Error)
		if ok && pkcs11Err == pkcs11.CKR_SIGNATURE_INVALID {
			// Signature is invalid, but this is not an error condition
			return false, nil
		}
		// Actual error occurred during verification
		return false, fmt.Errorf("failed to verify signature: %w", err)
	}

	// Verification successful
	return true, nil
}

func (c *SoftHSMClient) Encrypt(ctx context.Context, keyHandle string, plaintext []byte) ([]byte, error) {
	// Find the public key by label (persistent identifier)
	handle, err := c.findPublicKeyByLabel(keyHandle)
	if err != nil {
		return nil, fmt.Errorf(keyNotFoundErrMsg, keyHandle, err)
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if c.closed {
		return nil, errors.New(hsmClosedMsg)
	}

	// Usar mecanismo RSA PKCS para encriptación
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)

	err = c.ctx.EncryptInit(c.session, []*pkcs11.Mechanism{mechanism}, handle)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}

	ciphertext, err := c.ctx.Encrypt(c.session, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return ciphertext, nil
}

func (c *SoftHSMClient) Decrypt(ctx context.Context, keyHandle string, ciphertext []byte) ([]byte, error) {
	// Find the private key by label (persistent identifier)
	handle, err := c.findPrivateKeyByLabel(keyHandle)
	if err != nil {
		return nil, fmt.Errorf(keyNotFoundErrMsg, keyHandle, err)
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if c.closed {
		return nil, errors.New(hsmClosedMsg)
	}

	// Usar mecanismo RSA PKCS para desencriptación
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)

	err = c.ctx.DecryptInit(c.session, []*pkcs11.Mechanism{mechanism}, handle)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize decryption: %w", err)
	}

	plaintext, err := c.ctx.Decrypt(c.session, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
