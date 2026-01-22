package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/output"
)

type MySQLKeyOperationStorage struct {
	db *sql.DB
}

var _ output.KeyOperationRepository = (*MySQLKeyOperationStorage)(nil)

func NewMySQLKeyOperationStorage(db *sql.DB) output.KeyOperationRepository {
	return &MySQLKeyOperationStorage{db: db}
}

// Save implements [output.KeyOperationRepository].
func (m *MySQLKeyOperationStorage) Save(ctx context.Context, key entities.KeyOperation) error {
	query := `
		INSERT INTO key_operations (
			key_id,
			tenant_id,
			organization_id,
			operation_type,
			status,
			level,
			initiated_by,
			session_id,
			request_id,
			input_size_bytes,
			output_size_bytes,
			duration_ms,
			result_summary,
			error_details
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := m.db.ExecContext(ctx, query,
		key.KeyID,
		key.TenantID,
		&key.OrganizationID,
		string(key.OperationType),
		string(key.Status),
		string(key.Level),
		key.InitializedBy,
		key.SessionID,
		key.RequestID,
		key.InputSizeBytes,
		key.OutputSizeBytes,
		key.DurationMs,
		key.ResultSummary,
		key.ErrorDetails,
	)

	if err != nil {
		return fmt.Errorf("failed to save key operation: %w", err)
	}

	return nil
}
