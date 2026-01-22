package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/output"
)

// AuditRepository handles audit log persistence
type MySQLAuditStorage struct {
	db *sql.DB
}

var _ output.AuditStorage = (*MySQLAuditStorage)(nil)

// NewAuditRepository creates a new audit repository
func NewMySQLAuditStorage(db *sql.DB) *MySQLAuditStorage {
	return &MySQLAuditStorage{db: db}
}

// Save stores an audit event
func (r *MySQLAuditStorage) Store(ctx context.Context, event *entities.AuditEvent) error {
	query := ` INSERT INTO audit_logs (
			correlation_id,
			session_id,
			request_id,

			service_name,
			event_type,
			event_action,
			
			tenant_id,
			organization_id,
			user_id,
			resource_id,
			resource_type,

			actor_type,
			actor_id,
			
			success,
			status_code,
			error_message,
			duration_ms,
			
			ip_address,
			user_agent,
			
			metadata
		)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `
	metadataJSON, errj := json.Marshal(event.Metadata)
	if errj != nil {
		return fmt.Errorf("failed to marshal metadata: %w", errj)
	}

	_, err := r.db.ExecContext(ctx, query,
		event.CorrelationID,
		event.SessionID,
		event.RequestID,

		event.ServiceName,
		event.EventType,
		event.EventAction,

		event.TenantID,
		event.OrganizationID,
		event.UserID,
		event.ResourceID,
		event.ResourceType,

		event.ActorType,
		event.ActorID,

		event.Success,
		event.StatusCode,
		event.ErrorMessage,
		event.DurationMs,

		event.IPAddress,
		event.UserAgent,

		string(metadataJSON),
	)
	return err
}
