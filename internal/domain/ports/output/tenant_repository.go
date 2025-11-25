package output

import (
	"context"
	"hsm-service/internal/domain/entities"
)

type TenantRepository interface {
	FindByID(ctx context.Context, id string) (*entities.Tenant, error)
	Save(ctx context.Context, tenant *entities.Tenant) error
}
