package output

import (
	"context"
	"hsm-service/internal/domain/entities"
)

type AuditRepository interface {
	Save(ctx context.Context, event *entities.AuditEvent) error
}
