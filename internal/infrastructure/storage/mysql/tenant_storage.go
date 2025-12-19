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

type MySQLTenantStorage struct {
	db *sql.DB
}

// Garantiza implementación del puerto
var _ output.TenantRepository = (*MySQLTenantStorage)(nil)

func NewMySQLTenantStorage(db *sql.DB) output.TenantRepository {
	return &MySQLTenantStorage{db: db}
}

func (r *MySQLTenantStorage) FindByID(ctx context.Context, id string) (*entities.Tenant, error) {
	query := `
		SELECT id, name, contact_email, plan_type, 
		status, hsm_slot, created_at, updated_at
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
		&tenant.HSMSlot,
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

func (r *MySQLTenantStorage) Exists(ctx context.Context, id string) (bool, error) {
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

// FindByHSMSlot implements output.TenantRepository.
func (r *MySQLTenantStorage) FindByHSMSlot(ctx context.Context, slot uint) (*entities.Tenant, error) {
	query := `
		SELECT id, name, contact_email, plan_type, 
		status, hsm_slot, created_at, updated_at
		FROM tenants
		WHERE hsm_slot = ?
	`
	var tenant entities.Tenant
	err := r.db.QueryRowContext(ctx, query, slot).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.ContactEmail,
		&tenant.PlanType,
		&tenant.Status,
		&tenant.HSMSlot,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New(string(exceptions.ErrTenantNotFound))
	} else if err != nil {
		return nil, fmt.Errorf("failed to query tenant by HSM slot: %w", err)
	}
	return &tenant, nil
}
