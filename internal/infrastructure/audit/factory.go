package audit

import (
	"context"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"hsm-service/internal/infrastructure/transport/http"
)

// Factory crea el AuditRecorder basado en la estrategia configurada
func NewAuditRecorder(
	strategy valueobjects.AuditStrategy,
	storage output.AuditStorage,
	httpBaseURL string,
) (input.AuditRecorder, error) {

	// Siempre crear storage MySQL (fallback seguro)
	dbStorage := storage

	// Crear transporter HTTP si está configurado
	var httpTransporter output.AuditTransporter
	if httpBaseURL != "" && httpBaseURL != "mock" {
		httpTransporter = http.NewRestAuditClient(httpBaseURL)
	}

	// Si no hay transporter HTTP, forzar estrategia Database
	if httpTransporter == nil {
		// Si no hay HTTP, forzar estrategias que no dependan de él
		switch strategy {
		case valueobjects.StrategyHTTP:
			strategy = valueobjects.StrategyDatabase
		case valueobjects.StrategyHybrid:
			strategy = valueobjects.StrategyDatabase
		}
	}

	// Crear el recorder adecuado
	switch strategy {
	case valueobjects.StrategyDatabase:
		return &databaseRecorder{storage: dbStorage}, nil

	case valueobjects.StrategyHTTP:
		return &httpRecorder{transporter: httpTransporter}, nil

	case valueobjects.StrategyHybrid:
		return NewHybridProcessor(strategy, httpTransporter, dbStorage), nil

	case valueobjects.StrategyMock:
		return &mockRecorder{}, nil

	default:
		// Por defecto, usar database
		return &databaseRecorder{storage: dbStorage}, nil
	}
}

// databaseRecorder envía eventos directamente a la base de datos
type databaseRecorder struct {
	storage output.AuditStorage
}

func (r *databaseRecorder) RecordEvent(ctx context.Context, event *entities.AuditEvent) error {
	return r.storage.Store(ctx, event)
}

// httpRecorder envía eventos vía HTTP al servicio de auditoría
type httpRecorder struct {
	transporter output.AuditTransporter
}

func (r *httpRecorder) RecordEvent(ctx context.Context, event *entities.AuditEvent) error {
	return r.transporter.Send(ctx, event)
}

// mockRecorder para desarrollo/testing
type mockRecorder struct{}

func (r *mockRecorder) RecordEvent(ctx context.Context, event *entities.AuditEvent) error {
	// No-op en producción, podría loguear en desarrollo
	return nil
}
