package output

import (
	"context"
	"hsm-service/internal/domain/valueobjects"
)

// AuditEventDispatcher es el puerto de salida para enviar eventos de auditoría
// de forma asíncrona desde cualquier capa de la aplicación.
//
// Esta interfaz debe ser usada por:
// - Application Services (KeyService, SigningService, etc.)
// - Infrastructure Services (HSMClient, HSMManager)
//
// Implementaciones:
// - AuditWorker (async con workers)
// - MockAuditDispatcher (para tests)
// - NoOpAuditDispatcher (para deshabilitar auditoría)
type AuditEventDispatcher interface {
	// AuditOperation envía un evento de auditoría de forma asíncrona
	// ctx: contexto con metadata (tenant, request ID, etc.)
	// data: información de la operación a auditar
	AuditOperation(ctx context.Context, data valueobjects.AuditData)

	// Close cierra el dispatcher y libera recursos
	Close() error
}
