package output

import (
	"context"
	"hsm-service/internal/domain/entities"
)

// AuditTransporter para transporte externo (HTTP, Kafka, etc.)
type AuditTransporter interface {
	Send(ctx context.Context, event *entities.AuditEvent) error
	HealthCheck(ctx context.Context) error
}
