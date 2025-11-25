package output

import (
	"context"
	"platform-templates/templates/template-go-gin/internal/domain/entities"
)

type AuditRepository interface {
	Save(ctx context.Context, event *entities.AuditEvent) error
	FindByTenant(ctx context.Context, tenantID string, limit int) ([]*entities.AuditEvent, error)
	FindByResource(ctx context.Context, resourceID, resourceType string) ([]*entities.AuditEvent, error)
}