package input

import (
	"context"
	"hsm-service/internal/domain/entities"
)

type AuditRecorder interface {
	RecordEvent(ctx context.Context, event *entities.AuditEvent) error
	RecordSecurityEvent(ctx context.Context, action, actor, tenantID, resourceID, resourceType string) error
}
