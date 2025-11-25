package output

import (
	"context"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/valueobjects"
)

// HSMClient - Puerto de salida para comunicación con el HSM físico
type HSMClient interface {
	// Gestión de Claves
	GenerateKeyPair(ctx context.Context, algorithm valueobjects.KeyAlgorithm, size int, label string) (publicKey []byte, keyHandle string, err error)
	DeleteKey(ctx context.Context, keyHandle string) error
	ListKeys(ctx context.Context) ([]*entities.HSMKey, error)
	GetPublicKey(ctx context.Context, keyHandle string) ([]byte, error)

	// Operaciones Criptográficas
	SignHash(ctx context.Context, keyHandle string, hash []byte) ([]byte, error)
	VerifySignature(ctx context.Context, keyHandle string, hash, signature []byte) (bool, error)
	Encrypt(ctx context.Context, keyHandle string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, keyHandle string, ciphertext []byte) ([]byte, error)

	// Operaciones Extendidas para Multitenancy
	GenerateKeyPairWithLabel(ctx context.Context, algorithm valueobjects.KeyAlgorithm, size int, label, tenantID string) (publicKey []byte, keyHandle string, error error)
	FindKeysByLabel(ctx context.Context, labelPattern string) ([]*entities.HSMKey, error)
}
