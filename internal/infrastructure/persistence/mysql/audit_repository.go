package mysql

import (
	"context"
	"database/sql"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/valueobjects"
)

// AuditRepository handles audit log persistence
type mysqlAuditRepository struct {
	db *sql.DB
}

var _ input.AuditRecorder = (*mysqlAuditRepository)(nil)

// NewAuditRepository creates a new audit repository
func NewMySqlAuditRepository(db *sql.DB) input.AuditRecorder {
	return &mysqlAuditRepository{db: db}
}

// Save stores an audit event
func (r *mysqlAuditRepository) RecordEvent(ctx context.Context, event *entities.AuditEvent) error {
	tenantID, _ := valueobjects.TenantFromContext(ctx)

	query := ` INSERT INTO audit_logs 
		(tenant_id, event, payload, resource_id, resource_type,
		details, ip_address, user_agent) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `

	_, err := r.db.ExecContext(ctx, query, tenantID, event.Action, event.Metadata, event.ResourceID, event.ResourceType, event.Details, event.IPAddress, event.UserAgent)
	return err
}
