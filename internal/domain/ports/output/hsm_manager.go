package output

import (
	"context"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/valueobjects"
)

// HSMManager maneja múltiples clientes HSM por slot
type HSMManager interface {
	// GetClientForSlot obtiene cliente para slot específico
	GetClientForSlot(slot int) (HSMClient, error)

	// Métodos originales de HSMClient pero con slot
	GenerateKeyPair(
		ctx context.Context,
		algorithm valueobjects.KeyAlgorithm,
		size int,
		label string,
		slot int,
	) (publicKey []byte, keyHandle string, err error)
	DeleteKey(ctx context.Context, keyHandle string, slot int) error
	ListKeys(ctx context.Context, slot int) ([]*entities.HSMKey, error)
	GetPublicKey(ctx context.Context, keyHandle string, slot int) ([]byte, error)

	SignHash(ctx context.Context, keyHandle string, hash []byte, slot int) ([]byte, error)
	VerifySignature(ctx context.Context, keyHandle string, hash, signature []byte, slot int) (bool, error)
	Encrypt(ctx context.Context, keyHandle string, plaintext []byte, slot int) ([]byte, error)
	Decrypt(ctx context.Context, keyHandle string, ciphertext []byte, slot int) ([]byte, error)

	GenerateKeyPairWithLabel(
		ctx context.Context,
		algorithm valueobjects.KeyAlgorithm,
		size int,
		label,
		tenantID string,
		slot int,
	) (publicKey []byte, keyHandle string, error error)
	FindKeysByLabel(ctx context.Context, labelPattern string, slot int) ([]*entities.HSMKey, error)

	// Management
	HealthCheckAll() map[int]bool
	HealthCheck(ctx context.Context, slot int) error
	CloseAll() error
	Close(slot int) error
}
