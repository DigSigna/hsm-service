package input

import (
	"context"
)

// Signer - Puerto de entrada para operaciones de firmado
type Signer interface {
	SignHash(ctx context.Context, keyID string, hash []byte, tenantID string) ([]byte, error)
	GetPublicKey(ctx context.Context, keyID, tenantID string) ([]byte, error)
}