package input

import (
	"context"
	"hsm-service/internal/domain/entities"
)

// interfaz que usan TODOS los servicios
// Es lo que inyectamos en KeyService, CryptoService, etc.
type AuditRecorder interface {
	RecordEvent(ctx context.Context, event *entities.AuditEvent) error
}
