package input

import (
	"context"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/valueobjects"
)

// KeyManager - Puerto de entrada para gestión de claves
type KeyManager interface {
	CreateKey(ctx context.Context, name string, algorithm valueobjects.KeyAlgorithm, size int, usage valueobjects.KeyUsage, tenantID string) (*entities.CryptographicKey, error)
	GetKey(ctx context.Context, keyID, tenantID string) (*entities.CryptographicKey, error)
	ListKeys(ctx context.Context, tenantID string) ([]*entities.CryptographicKey, error)
	RotateKey(ctx context.Context, keyID, tenantID string) (*entities.CryptographicKey, error)
	DeleteKey(ctx context.Context, keyID, tenantID string) error
}
