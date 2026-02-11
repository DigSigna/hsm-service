package input

import (
	"context"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/valueobjects"
)

type HSMKeyManager interface {
	CreateHSMKey(ctx context.Context, label string, algorithm valueobjects.KeyAlgorithm, size int, tenantID string) (*entities.HSMKey, error)
	ListHSMKeys(ctx context.Context, tenantID string) ([]*entities.HSMKey, error)
	GetHSMPublicKey(ctx context.Context, keyLabel, tenantID string) ([]byte, error)
}
