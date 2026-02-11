package output

import (
	"context"
	"hsm-service/internal/domain/entities"
)

// interfaz para almacenar eventos
// Puede ser implementado por MySQL, HTTP, File, etc.
type AuditStorage interface {
	Store(ctx context.Context, event *entities.AuditEvent) error
	// HealthCheck() opcional
}
