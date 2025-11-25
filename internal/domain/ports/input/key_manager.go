package input

import (
	"context"
	"platform-templates/templates/template-go-gin/internal/domain/entities"
	"platform-templates/templates/template-go-gin/internal/domain/valueobjects"
)

// KeyManager - Puerto de entrada para gestión de claves
type KeyManager interface {
	CreateKey(ctx context.Context, name string, algorithm valueobjects.KeyAlgorithm, size int, usage entities.KeyUsage, tenantID string) (*entities.CryptographicKey, error)
	GetKey(ctx context.Context, keyID, tenantID string) (*entities.CryptographicKey, error)
	ListKeys(ctx context.Context, tenantID string) ([]*entities.CryptographicKey, error)
	RotateKey(ctx context.Context, keyID, tenantID string) (*entities.CryptographicKey, error)
	DeleteKey(ctx context.Context, keyID, tenantID string) error
}
