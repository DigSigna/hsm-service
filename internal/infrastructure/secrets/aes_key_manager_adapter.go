// internal/infrastructure/secrets/aes_key_manager_adapter.go
package secrets

import (
	"context"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"hsm-service/pkg/crypto"
	"hsm-service/pkg/helpers"
	"time"
)

type AESKeyManagerAdapter struct {
	strategy output.AESKeyManager
	audit    output.AuditEventDispatcher
}

var _ output.AESKeyManager = (*AESKeyManagerAdapter)(nil)

const servicesNameAESKeyManager = "aes-key-manager-adapter"

func NewAESKeyManagerAdapter(strategy output.AESKeyManager, audit output.AuditEventDispatcher) *AESKeyManagerAdapter {
	return &AESKeyManagerAdapter{
		strategy: strategy,
		audit:    audit,
	}
}

// GetKey implements [output.AESKeyManager]
func (a *AESKeyManagerAdapter) GetKey(ctx context.Context, keyID string) (key []byte, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: servicesNameAESKeyManager,
			EventType:   "HSM_OPERATION", //AES_OPERATION
			Operation:   "get_key",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			ResourceID:  keyID,
		}
		if a.audit != nil {
			a.audit.AuditOperation(ctx, data, nil)
		}
	}()

	return a.strategy.GetKey(ctx, keyID)
}

// GenerateDataKey implements [output.AESKeyManager]
func (a *AESKeyManagerAdapter) GenerateDataKey() (key []byte, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: servicesNameAESKeyManager,
			EventType:   "HSM_OPERATION", //AES_OPERATION
			Operation:   "generate_data_key",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
		}
		if a.audit != nil {
			a.audit.AuditOperation(context.Background(), data, nil)
		}
	}()

	return a.strategy.GenerateDataKey()
}

// WrapKey implements [output.AESKeyManager]
func (a *AESKeyManagerAdapter) WrapKey(ctx context.Context, keyID string, plaintextKey []byte) (wrappedKey []byte, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: servicesNameAESKeyManager,
			EventType:   "HSM_OPERATION", //AES_OPERATION
			Operation:   "wrap_key",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			ResourceID:  keyID,
			Metadata: map[string]interface{}{
				"plaintext_key_length": len(plaintextKey),
			},
		}
		if a.audit != nil {
			a.audit.AuditOperation(ctx, data, nil)
		}
	}()

	return a.strategy.WrapKey(ctx, keyID, plaintextKey)
}

// UnwrapKey implements [output.AESKeyManager]
func (a *AESKeyManagerAdapter) UnwrapKey(ctx context.Context, keyID string, wrappedKey []byte) (plaintextKey []byte, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: servicesNameAESKeyManager,
			EventType:   "HSM_OPERATION", //AES_OPERATION
			Operation:   "unwrap_key",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			ResourceID:  keyID,
			Metadata: map[string]interface{}{
				"wrapped_key_length": len(wrappedKey),
			},
		}
		if a.audit != nil {
			a.audit.AuditOperation(ctx, data, nil)
		}
	}()

	return a.strategy.UnwrapKey(ctx, keyID, wrappedKey)
}

// Encrypt implements [output.AESKeyManager]
func (a *AESKeyManagerAdapter) EncryptWithKeyID(
	ctx context.Context,
	keyID string,
	plaintext []byte,
) (encryptedData *valueobjects.EncryptAESGCM, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: servicesNameAESKeyManager,
			EventType:   "HSM_OPERATION", //AES_OPERATION
			Operation:   "encrypt_aes_gcm",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			ResourceID:  keyID,
			Metadata: map[string]interface{}{
				"plaintext_length": len(plaintext),
			},
		}
		if a.audit != nil {
			a.audit.AuditOperation(ctx, data, nil)
		}
	}()

	key, err := a.strategy.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	encrypted, err := crypto.EncryptAESGCM(key, plaintext)
	if err != nil {
		return nil, err
	}

	encrypted.KeyID = keyID

	return encrypted, nil
}

// Decrypt implements [output.AESKeyManager]
func (a *AESKeyManagerAdapter) DecryptWithKeyID(
	ctx context.Context,
	keyID string,
	encrypted valueobjects.EncryptAESGCM,
) (plainData []byte, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: servicesNameAESKeyManager,
			EventType:   "HSM_OPERATION", //AES_OPERATION
			Operation:   "decrypt_aes_gcm",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			ResourceID:  keyID,
			Metadata: map[string]interface{}{
				"encrypted_length": len(encrypted.Ciphertext),
			},
		}
		if a.audit != nil {
			a.audit.AuditOperation(ctx, data, nil)
		}
	}()

	if encrypted.KeyID != keyID {
		return nil, exceptions.DomainErrKeyIDMismatch
	}

	key, err := a.strategy.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	return crypto.DecryptAESGCM(key, encrypted)
}

// Encrypt implements [output.AESKeyManager]
func (a *AESKeyManagerAdapter) EncryptWithKey(
	key,
	plaintext []byte,
) (encryptedData *valueobjects.EncryptAESGCM, err error) {
	ctx := context.Background()
	start := time.Now()

	keyID := a.GetCurrentKeyID()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: servicesNameAESKeyManager,
			EventType:   "HSM_OPERATION", //AES_OPERATION
			Operation:   "encrypt_aes_gcm",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			ResourceID:  keyID,
			Metadata: map[string]interface{}{
				"plaintext_length": len(plaintext),
			},
		}
		if a.audit != nil {
			a.audit.AuditOperation(ctx, data, nil)
		}
	}()

	encrypted, err := crypto.EncryptAESGCM(key, plaintext)
	if err != nil {
		return nil, err
	}

	encrypted.KeyID = keyID

	return encrypted, nil
}

// Decrypt implements [output.AESKeyManager]
func (a *AESKeyManagerAdapter) DecryptWithKey(
	key []byte,
	encrypted valueobjects.EncryptAESGCM,
) (plainData []byte, err error) {
	ctx := context.Background()
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: servicesNameAESKeyManager,
			EventType:   "HSM_OPERATION", //AES_OPERATION
			Operation:   "decrypt_aes_gcm",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			ResourceID:  encrypted.KeyID,
			Metadata: map[string]interface{}{
				"encrypted_length": len(encrypted.Ciphertext),
			},
		}
		if a.audit != nil {
			a.audit.AuditOperation(ctx, data, nil)
		}
	}()

	return crypto.DecryptAESGCM(key, encrypted)
}

func (a *AESKeyManagerAdapter) RewrapKey(
	ctx context.Context,
	oldKeyID, newKeyID string,
	wrappedKey []byte,
) ([]byte, error) {
	return a.strategy.RewrapKey(ctx, oldKeyID, newKeyID, wrappedKey)
}

func (a *AESKeyManagerAdapter) ListKeyVersions(ctx context.Context) ([]string, error) {
	return a.strategy.ListKeyVersions(ctx)
}

func (a *AESKeyManagerAdapter) GetCurrentKeyID() string {
	return a.strategy.GetCurrentKeyID()
}
