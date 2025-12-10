package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/output"

	_ "github.com/go-sql-driver/mysql"
)

type mysqlTenantRepository struct {
	db *sql.DB
}

// Garantiza implementación del puerto
var _ output.TenantRepository = (*mysqlTenantRepository)(nil)

func NewMySqlTenantRepository(db *sql.DB) output.TenantRepository {
	return &mysqlTenantRepository{db: db}
}

func (r *mysqlTenantRepository) FindByID(ctx context.Context, id string) (*entities.Tenant, error) {
	query := `
		SELECT id, name, contact_email, plan_type, status, created_at, updated_at
		FROM tenants
		WHERE id = ?
	`
	var tenant entities.Tenant

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.ContactEmail,
		&tenant.PlanType,
		&tenant.Status,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New(string(exceptions.ErrTenantNotFound))
	} else if err != nil {
		return nil, fmt.Errorf("failed to query tenant by ID: %w", err)
	}
	return &tenant, nil
}

func (r *mysqlTenantRepository) Exists(ctx context.Context, id string) (bool, error) {
	query := `
		SELECT COUNT(1)
		FROM tenants
		WHERE id = ?
	`
	var count int
	err := r.db.QueryRowContext(ctx, query, id).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check tenant existence: %w", err)
	}
	return count > 0, nil
}
