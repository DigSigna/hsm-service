package input

import (
	"context"
)

type CryptoService interface {
	// Firma y Verificación
	SignData(ctx context.Context, keyLabel string, data []byte, tenantID string) ([]byte, error)
	VerifySignature(ctx context.Context, keyLabel string, data, signature []byte, tenantID string) (bool, error)

	// Encriptación/Desencriptación
	EncryptData(ctx context.Context, keyLabel string, plaintext []byte, tenantID string) ([]byte, error)
	DecryptData(ctx context.Context, keyLabel string, ciphertext []byte, tenantID string) ([]byte, error)

	// Operaciones con Hash
	SignHash(ctx context.Context, keyLabel string, hash []byte, tenantID string) ([]byte, error)
	VerifyHashSignature(ctx context.Context, keyLabel string, hash, signature []byte, tenantID string) (bool, error)
}
