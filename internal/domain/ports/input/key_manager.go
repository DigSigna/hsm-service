package input

import (
	"context"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/valueobjects"
)

// KeyManager - Puerto de entrada para gestión de claves
type KeyManager interface {
	// Operaciones existentes (mantener compatibilidad)
	CreateKey(ctx context.Context, name string, algorithm valueobjects.KeyAlgorithm, size int, usage valueobjects.KeyUsage, tenantID string) (*entities.CryptographicKey, error)
	GetKey(ctx context.Context, keyID, tenantID string) (*entities.CryptographicKey, error)
	ListKeys(ctx context.Context, tenantID string) ([]*entities.CryptographicKey, error)
	RotateKey(ctx context.Context, keyID, tenantID string) (*entities.CryptographicKey, error)
	DeleteKey(ctx context.Context, keyID, tenantID string) error

	// Nuevas operaciones para HSM directo
	CreateHSMKey(ctx context.Context, label string, algorithm valueobjects.KeyAlgorithm, size int, tenantID string) (*entities.HSMKey, error)
	ListHSMKeys(ctx context.Context, tenantID string) ([]*entities.HSMKey, error)
	GetHSMPublicKey(ctx context.Context, keyLabel, tenantID string) ([]byte, error)
}
