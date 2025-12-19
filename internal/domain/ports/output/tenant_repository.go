package output

import (
	"context"
	"hsm-service/internal/domain/entities"
)

type TenantRepository interface {
	FindByID(ctx context.Context, id string) (*entities.Tenant, error)
	Exists(ctx context.Context, id string) (bool, error)
	FindByHSMSlot(ctx context.Context, slot uint) (*entities.Tenant, error)
}
