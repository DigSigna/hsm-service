package input

import (
	"context"
	"hsm-service/internal/domain/valueobjects"
)

// Signer - Puerto de entrada para operaciones de firmado
type Signer interface {
	SignHash(
		ctx context.Context,
		keyID string,
		hash []byte,
		identityContext *valueobjects.IdentityContext,
	) ([]byte, error)
	VerifyHashSignature(
		ctx context.Context,
		keyID string,
		hash, signature []byte,
		identityContext *valueobjects.IdentityContext,
	) (bool, error)
	GetPublicKey(ctx context.Context, keyID, tenantID string) ([]byte, error)
}
