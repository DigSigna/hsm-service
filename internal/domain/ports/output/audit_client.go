package output

import (
	"context"
	"hsm-service/internal/domain/entities"
)

// AuditClient define el contrato para el cliente de auditoría
type AuditClient interface {
	LogSecurityEvent(ctx context.Context, event entities.AuditEvent) error
	LogBusinessEvent(ctx context.Context, event entities.AuditEvent) error
	LogSystemEvent(ctx context.Context, event entities.AuditEvent) error
	Close() error
}
