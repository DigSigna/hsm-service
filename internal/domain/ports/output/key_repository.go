package output

import (
	"context"
	"platform-templates/templates/template-go-gin/internal/domain/entities"
)

// KeyRepository - Puerto de salida para persistencia de metadatos de claves
type KeyRepository interface {
	Save(ctx context.Context, key *entities.CryptographicKey) error
	FindByID(ctx context.Context, id string) (*entities.CryptographicKey, error)
	FindByIDAndTenant(ctx context.Context, id, tenantID string) (*entities.CryptographicKey, error)
	FindByTenant(ctx context.Context, tenantID string) ([]*entities.CryptographicKey, error)
	Delete(ctx context.Context, id string) error
}