package input

import (
	"context"
	"platform-templates/templates/template-go-gin/internal/domain/entities"
)

type AuditRecorder interface {
	RecordEvent(ctx context.Context, event *entities.AuditEvent) error
	RecordSecurityEvent(ctx context.Context, action, actor, tenantID, resourceID, resourceType string) error
}