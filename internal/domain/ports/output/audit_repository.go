package output

import (
	"context"
	"hsm-service/internal/domain/entities"
)

type AuditRepository interface {
	Save(ctx context.Context, event *entities.AuditEvent) error
	FindByTenant(ctx context.Context, tenantID string, limit int) ([]*entities.AuditEvent, error)
	FindByResource(ctx context.Context, resourceID, resourceType string) ([]*entities.AuditEvent, error)
}
