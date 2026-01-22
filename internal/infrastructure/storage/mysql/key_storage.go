package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type MySQLKeyStorage struct {
	db *sql.DB
}

// Garantiza implementación del puerto
var _ output.KeyRepository = (*MySQLKeyStorage)(nil)

func NewMySQLKeyStorage(db *sql.DB) output.KeyRepository {
	return &MySQLKeyStorage{db: db}
}

func (r *MySQLKeyStorage) Save(ctx context.Context, key *entities.CryptographicKey) error {
	query := `
		INSERT INTO crypto_keys (
			id,
			tenant_id,

			owner_type,
			owner_id,
			parent_key_id,
			cert_level,

			name,
			alias,

			algorithm,
			key_size,
			purpose,
			
			public_key,
			key_handle,
			key_label,

			is_hardware_backed,
			hsm_slot,

			expiration_date,

			is_active,
			version
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := r.db.ExecContext(ctx, query,
		key.ID,
		key.TenantID,

		string(key.OwnerType),
		key.OwnerID,
		key.ParentKeyID,
		key.CertLevel,

		key.Name,
		key.Alias,

		string(key.Algorithm),
		key.KeySize,
		string(key.Purpose),

		key.PublicKey,
		key.KeyHandle,
		key.KeyLabel,

		true, //is_hardware_backed
		key.HSMSlot,

		key.ExpirationDate,

		key.IsActive,
		key.Version,
	)

	if err != nil {
		println("Parent key ID:", key.ParentKeyID)
		println("Error saving key---:", err.Error())
		return fmt.Errorf("failed to get last insert id: %w", err)
	}

	return nil
}

func (r *MySQLKeyStorage) FindByID(ctx context.Context, id string) (*entities.CryptographicKey, error) {
	log.Println("Finding key by ID:", id)
	query := `
		SELECT id, name, public_key, created_at, expiration_date, is_active
		FROM crypto_keys
		WHERE id = ?
	`

	var key entities.CryptographicKey
	var algorithmStr, usageStr string
	var createdAt, expiredAt time.Time
	var isActive bool

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&key.ID,
		&key.Name,
		&key.PublicKey,
		&createdAt,
		&key.ExpirationDate,
		&key.IsActive,
	)

	if err == sql.ErrNoRows {
		log.Println("Key not found with ID:", id)
		return nil, exceptions.NewDomainError(
			exceptions.ErrKeyNotFound,
			"key not found",
		).WithDetail("original_error", err.Error())
	} else if err != nil {
		log.Println("Error finding key by ID:", err)
		// return nil, fmt.Errorf("failed to find key: %w", err)
		return nil, exceptions.NewDomainError(
			exceptions.ErrKeyNotFound,
			"Error finding key",
		).WithDetail("original_error", err.Error())
	}

	// Convertir string a KeyAlgorithm
	key.Algorithm = valueobjects.KeyAlgorithm(algorithmStr)
	key.Purpose = valueobjects.KeyUsage(usageStr)
	key.CreatedAt = createdAt
	key.ExpirationDate = expiredAt
	key.IsActive = isActive

	return &key, nil
}

func (r *MySQLKeyStorage) FindByIDAndTenant(ctx context.Context, id, tenantID string) (*entities.CryptographicKey, error) {
	query := `
		SELECT id, name, algorithm, key_size, purpose, public_key, key_handle, tenant_id, version, created_at, is_active
		FROM crypto_keys
		WHERE id = ? AND tenant_id = ?
	`

	var key entities.CryptographicKey
	var algorithmStr, usageStr string
	var createdAt time.Time

	err := r.db.QueryRowContext(ctx, query, id, tenantID).Scan(
		&key.ID,
		&key.Name,
		&algorithmStr,
		&key.KeySize,
		&usageStr,
		&key.PublicKey,
		&key.KeyHandle,
		&key.TenantID,
		&key.Version,
		&createdAt,
		&key.IsActive,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New(string(exceptions.ErrKeyNotFound))
	} else if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}

	key.Algorithm = valueobjects.KeyAlgorithm(algorithmStr)
	key.Purpose = valueobjects.KeyUsage(usageStr)
	key.CreatedAt = createdAt

	return &key, nil
}

func (r *MySQLKeyStorage) FindByTenant(ctx context.Context, tenantID string) ([]*entities.CryptographicKey, error) {
	query := `
		SELECT id, name, alias, 
			algorithm, key_size, purpose,
			public_key, key_handle, key_label,
			tenant_id,
			version, is_active,
			created_at, expiration_date 
		FROM crypto_keys
		WHERE tenant_id = ?
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query keys: %w", err)
	}
	defer rows.Close()

	var keys []*entities.CryptographicKey
	for rows.Next() {
		var key entities.CryptographicKey
		var algorithmStr, usageStr string
		var createdAt time.Time
		// time or null
		var expiredAt sql.NullTime

		if err := rows.Scan(
			&key.ID,
			&key.Name,
			&key.Alias,
			&algorithmStr,
			&key.KeySize,
			&key.Purpose,
			&key.PublicKey,
			&key.KeyHandle,
			&key.KeyLabel,
			&key.TenantID,
			&key.Version,
			&key.IsActive,
			&createdAt,
			&expiredAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}

		key.Algorithm = valueobjects.KeyAlgorithm(algorithmStr)
		key.Purpose = valueobjects.KeyUsage(usageStr)
		key.CreatedAt = createdAt
		if expiredAt.Valid {
			key.ExpirationDate = expiredAt.Time
		}

		keys = append(keys, &key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return keys, nil
}

// FindByOwner implements [output.KeyRepository].
func (r *MySQLKeyStorage) FindByOwner(ctx context.Context, ownerID string) (*entities.CryptographicKey, error) {
	query := `
		SELECT id, name, algorithm, key_size, purpose, public_key, key_handle, tenant_id, version, created_at, is_active
		FROM crypto_keys
		WHERE owner_id = ?
	`

	var key entities.CryptographicKey
	var algorithmStr, usageStr string
	var createdAt time.Time

	err := r.db.QueryRowContext(ctx, query, ownerID).Scan(
		&key.ID,
		&key.Name,
		&algorithmStr,
		&key.KeySize,
		&usageStr,
		&key.PublicKey,
		&key.KeyHandle,
		&key.TenantID,
		&key.Version,
		&createdAt,
		&key.IsActive,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New(string(exceptions.ErrKeyNotFound))
	} else if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}

	key.Algorithm = valueobjects.KeyAlgorithm(algorithmStr)
	key.Purpose = valueobjects.KeyUsage(usageStr)
	key.CreatedAt = createdAt

	return &key, nil
}

// FindByOwnerType implements [output.KeyRepository].
func (r *MySQLKeyStorage) FindByOwnerType(ctx context.Context, ownerType string) ([]*entities.CryptographicKey, error) {
	query := `
		SELECT id, name, alias, 
			algorithm, key_size, purpose,
			public_key, key_handle, key_label,
			tenant_id,
			version, is_active,
			created_at, expiration_date 
		FROM crypto_keys
		WHERE owner_type = ?
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, ownerType)
	if err != nil {
		return nil, fmt.Errorf("failed to query keys: %w", err)
	}
	defer rows.Close()

	var keys []*entities.CryptographicKey
	for rows.Next() {
		var key entities.CryptographicKey
		var algorithmStr, usageStr string
		var createdAt time.Time
		// time or null
		var expiredAt sql.NullTime

		if err := rows.Scan(
			&key.ID,
			&key.Name,
			&key.Alias,
			&algorithmStr,
			&key.KeySize,
			&key.Purpose,
			&key.PublicKey,
			&key.KeyHandle,
			&key.KeyLabel,
			&key.TenantID,
			&key.Version,
			&key.IsActive,
			&createdAt,
			&expiredAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}

		key.Algorithm = valueobjects.KeyAlgorithm(algorithmStr)
		key.Purpose = valueobjects.KeyUsage(usageStr)
		key.CreatedAt = createdAt
		if expiredAt.Valid {
			key.ExpirationDate = expiredAt.Time
		}

		keys = append(keys, &key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return keys, nil
}

func (r *MySQLKeyStorage) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM crypto_keys WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.New(string(exceptions.ErrKeyNotFound))
	}

	return nil
}
