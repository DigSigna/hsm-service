package output

import (
	"context"
	"hsm-service/internal/domain/valueobjects"
)

// Key Management Service Provider Interface
// This interface defines methods for encrypting, decrypting, and deriving keys,
// used by the application to interact with a slots secure PIN management system.
type AESKeyManager interface {
	GetKey(ctx context.Context, keyID string) (key []byte, err error)
	// Generate aleatory AES-256 key (32 bytes)
	GenerateDataKey() (key []byte, err error)
	WrapKey(ctx context.Context, keyID string, plaintextKey []byte) (wrappedKey []byte, err error)
	UnwrapKey(ctx context.Context, keyID string, wrappedKey []byte) (plaintextKey []byte, err error)

	// Rotación de claves
	RewrapKey(ctx context.Context, oldKeyID, newKeyID string, wrappedKey []byte) (newWrappedKey []byte, err error)

	// Encrypt/Decrypt con keyID (para cuando la clave está en almacén)
	EncryptWithKeyID(ctx context.Context, keyID string, plaintext []byte) (encrypted *valueobjects.EncryptAESGCM, err error)
	DecryptWithKeyID(ctx context.Context, keyID string, encrypted valueobjects.EncryptAESGCM) (plaintext []byte, err error)

	// Encrypt/Decrypt con clave en memoria (para slotKey, etc.)
	EncryptWithKey(key []byte, plaintext []byte) (encrypted *valueobjects.EncryptAESGCM, err error)
	DecryptWithKey(key []byte, encrypted valueobjects.EncryptAESGCM) (plaintext []byte, err error)

	// Métodos para gestión de versiones (opcional)
	ListKeyVersions(ctx context.Context) ([]string, error)
	GetCurrentKeyID() string
}
