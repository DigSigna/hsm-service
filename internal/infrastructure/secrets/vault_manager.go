package secrets

import (
	// "context"
	// "encoding/base64"
	"context"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	// "hsm-service/internal/domain/valueobjects"
)

type VaultAESKeyManager struct {
	// client    *vault.Client
	mountPath string
}

var _ output.AESKeyManager = (*VaultAESKeyManager)(nil)

func NewVaultAESKeyManager(config VaultConfig) *VaultAESKeyManager {
	return &VaultAESKeyManager{
		mountPath: config.Address,
	}
}

// DecryptWithKey implements [output.AESKeyManager].
func (v *VaultAESKeyManager) DecryptWithKey(key []byte, encrypted valueobjects.EncryptAESGCM) (plaintext []byte, err error) {
	panic("unimplemented")
}

// DecryptWithKeyID implements [output.AESKeyManager].
func (v *VaultAESKeyManager) DecryptWithKeyID(ctx context.Context, keyID string, encrypted valueobjects.EncryptAESGCM) (plaintext []byte, err error) {
	panic("unimplemented")
}

// EncryptWithKey implements [output.AESKeyManager].
func (v *VaultAESKeyManager) EncryptWithKey(key []byte, plaintext []byte) (encrypted *valueobjects.EncryptAESGCM, err error) {
	panic("unimplemented")
}

// EncryptWithKeyID implements [output.AESKeyManager].
func (v *VaultAESKeyManager) EncryptWithKeyID(ctx context.Context, keyID string, plaintext []byte) (encrypted *valueobjects.EncryptAESGCM, err error) {
	panic("unimplemented")
}

// GenerateDataKey implements [output.AESKeyManager].
func (v *VaultAESKeyManager) GenerateDataKey() (key []byte, err error) {
	panic("unimplemented")
}

// GetCurrentKeyID implements [output.AESKeyManager].
func (v *VaultAESKeyManager) GetCurrentKeyID() string {
	panic("unimplemented")
}

// GetKey implements [output.AESKeyManager].
func (v *VaultAESKeyManager) GetKey(ctx context.Context, keyID string) (key []byte, err error) {
	panic("unimplemented")
}

// ListKeyVersions implements [output.AESKeyManager].
func (v *VaultAESKeyManager) ListKeyVersions(ctx context.Context) ([]string, error) {
	panic("unimplemented")
}

// RewrapKey implements [output.AESKeyManager].
func (v *VaultAESKeyManager) RewrapKey(ctx context.Context, oldKeyID string, newKeyID string, wrappedKey []byte) (newWrappedKey []byte, err error) {
	panic("unimplemented")
}

// UnwrapKey implements [output.AESKeyManager].
func (v *VaultAESKeyManager) UnwrapKey(ctx context.Context, keyID string, wrappedKey []byte) (plaintextKey []byte, err error) {
	panic("unimplemented")
}

// WrapKey implements [output.AESKeyManager].
func (v *VaultAESKeyManager) WrapKey(ctx context.Context, keyID string, plaintextKey []byte) (wrappedKey []byte, err error) {
	panic("unimplemented")
}
