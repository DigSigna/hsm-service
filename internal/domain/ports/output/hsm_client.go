package output

import (
	"context"
	"platform-templates/templates/template-go-gin/internal/domain/valueobjects"
)

// HSMClient - Puerto de salida para comunicación con el HSM físico
type HSMClient interface {
	GenerateKeyPair(ctx context.Context, algorithm valueobjects.KeyAlgorithm, size int) (publicKey []byte, keyHandle string, error error)
	SignHash(ctx context.Context, keyHandle string, hash []byte) ([]byte, error)
	GetPublicKey(ctx context.Context, keyHandle string) ([]byte, error)
	DeleteKey(ctx context.Context, keyHandle string) error
}
