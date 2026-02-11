// internal/infrastructure/secrets/local_manager.go
package secrets

import (
	"context"
	"encoding/base64"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"hsm-service/pkg/crypto"
)

type LocalAESKeyManager struct {
	masterKey []byte // Solo la clave, sin auditoría
	keyID     string
}

var _ output.AESKeyManager = (*LocalAESKeyManager)(nil)

func NewLocalAESKeyManager(config LocalConfig) *LocalAESKeyManager {
	masterKey, _ := base64.StdEncoding.DecodeString(config.MasterKeyKey)
	return &LocalAESKeyManager{
		masterKey: masterKey,
		keyID:     config.KeyID,
	}
}

func (l *LocalAESKeyManager) GetKey(ctx context.Context, keyID string) (key []byte, err error) {
	// En estrategia local, siempre la misma master key
	return l.masterKey, nil
}

func (l *LocalAESKeyManager) GenerateDataKey() (key []byte, err error) {
	return crypto.GenerateAES256Key()
}

func (l *LocalAESKeyManager) WrapKey(ctx context.Context, keyID string, plaintextKey []byte) (wrappedKey []byte, err error) {
	masterKey, err := l.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if len(plaintextKey) != 32 {
		return nil, exceptions.DomainErrInvalidAESKeySize.
			WithDetail("expected", 32).
			WithDetail("actual", len(plaintextKey))
	}

	return crypto.WrapKey(masterKey, plaintextKey)
}

func (l *LocalAESKeyManager) UnwrapKey(ctx context.Context, keyID string, wrappedKey []byte) (plaintextKey []byte, err error) {
	masterKey, err := l.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	if len(wrappedKey) < 28 {
		return nil, exceptions.DomainErrWrappingKeyLength.
			WithDetail("minimum_expected", 28).
			WithDetail("actual", len(wrappedKey))
	}

	return crypto.UnwrapKey(masterKey, wrappedKey)
}

func (l *LocalAESKeyManager) EncryptWithKeyID(ctx context.Context, keyID string, plaintext []byte) (encrypt *valueobjects.EncryptAESGCM, err error) {
	key, err := l.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	encrypted, err := crypto.EncryptAESGCM(key, plaintext)
	if err != nil {
		return nil, exceptions.DomainErrFailEncryptData.
			WithDetail("error", err.Error())
	}

	encrypted.KeyID = keyID
	return encrypted, nil
}

func (l *LocalAESKeyManager) DecryptWithKeyID(ctx context.Context, keyID string, encrypted valueobjects.EncryptAESGCM) (plaintext []byte, err error) {
	if encrypted.KeyID != keyID {
		return nil, exceptions.DomainErrKeyIDMismatch
	}

	key, err := l.GetKey(ctx, keyID)
	if err != nil {
		return nil, err
	}

	return crypto.DecryptAESGCM(key, encrypted)
}

func (l *LocalAESKeyManager) EncryptWithKey(
	key []byte,
	plaintext []byte,
) (encrypted *valueobjects.EncryptAESGCM, err error) {
	if len(key) != 32 {
		return nil, exceptions.DomainErrInvalidAESKeySize.
			WithDetail("expected", 32).
			WithDetail("actual", len(key))
	}
	encrypted, err = crypto.EncryptAESGCM(key, []byte(plaintext))
	if err != nil {
		return nil, exceptions.DomainErrFailEncryptData.
			WithDetail("error", err.Error())
	}

	encrypted.KeyID = l.keyID

	return encrypted, nil
}
func (l *LocalAESKeyManager) DecryptWithKey(
	key []byte,
	encrypted valueobjects.EncryptAESGCM,
) (plaintext []byte, err error) {
	println("DEBUG: Decrypt function Local manager")
	if len(key) != 32 {
		return nil, exceptions.DomainErrInvalidAESKeySize.
			WithDetail("expected", 32).
			WithDetail("actual", len(key))
	}

	plaintext, err = crypto.DecryptAESGCM(key, encrypted)

	if err != nil {
		println("DEBUG: Error in local")
		return nil, exceptions.DomainErrFailDecryptData.
			WithDetail("error", err.Error())
	}
	return plaintext, nil
}

func (l *LocalAESKeyManager) RewrapKey(
	ctx context.Context,
	oldKeyID, newKeyID string,
	wrappedKey []byte,
) ([]byte, error) {
	// 1. Desenvolver con la clave antigua
	oldKey, err := l.GetKey(ctx, oldKeyID)
	if err != nil {
		return nil, exceptions.DomainErrK8sSecretNotFound.WithDetail("original_error", err.Error())
	}

	plaintextKey, err := crypto.UnwrapKey(oldKey, wrappedKey)
	if err != nil {
		return nil, exceptions.DomainErrFailUUnwrapKey.WithDetail("original_error", err.Error())
	}

	// 2. Envolver con la clave nueva
	newKey, err := l.GetKey(ctx, newKeyID)
	if err != nil {
		zeroBytes(plaintextKey)
		return nil, exceptions.DomainErrK8sSecretNotFound.WithDetail("original_error", err.Error())
	}

	newWrappedKey, err := crypto.WrapKey(newKey, plaintextKey)
	if err != nil {
		zeroBytes(plaintextKey)
		return nil, exceptions.DomainErrFailWrapKey.WithDetail("original_error", err.Error())
	}

	// 3. Limpiar
	zeroBytes(plaintextKey)

	return newWrappedKey, nil
}

func (l *LocalAESKeyManager) ListKeyVersions(ctx context.Context) ([]string, error) {
	panic("not implemented")
}

func (l *LocalAESKeyManager) GetCurrentKeyID() string {
	return l.keyID
}

// Función helper para limpiar bytes sensibles
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
