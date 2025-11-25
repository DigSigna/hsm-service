package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

const errFailedToUnmarshalMetadata = "failed to unmarshal metadata"

type postgresKeyRepository struct {
	db *sql.DB
}

// Garantiza implementación del puerto
var _ output.KeyRepository = (*postgresKeyRepository)(nil)

func NewPostgresKeyRepository(db *sql.DB) output.KeyRepository {
	return &postgresKeyRepository{db: db}
}

func (r *postgresKeyRepository) Save(ctx context.Context, key *entities.CryptographicKey) error {
	query := `
		INSERT INTO cryptographic_keys (id, name, algorithm, key_size, usage, public_key, key_handle, tenant_id, version, created_at, is_active, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			algorithm = EXCLUDED.algorithm,
			key_size = EXCLUDED.key_size,
			usage = EXCLUDED.usage,
			public_key = EXCLUDED.public_key,
			key_handle = EXCLUDED.key_handle,
			tenant_id = EXCLUDED.tenant_id,
			version = EXCLUDED.version,
			created_at = EXCLUDED.created_at,
			is_active = EXCLUDED.is_active,
			metadata = EXCLUDED.metadata
	`

	// Convertir metadata a JSONB
	metadataJSON, err := json.Marshal(key.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = r.db.ExecContext(ctx, query,
		key.ID,
		key.Name,
		string(key.Algorithm),
		key.KeySize,
		string(key.Usage),
		key.PublicKey,
		key.KeyHandle,
		key.TenantID,
		key.Version,
		key.CreatedAt,
		key.IsActive,
		metadataJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	return nil
}

func (r *postgresKeyRepository) FindByID(ctx context.Context, id string) (*entities.CryptographicKey, error) {
	query := `
		SELECT id, name, algorithm, key_size, usage, public_key, key_handle, tenant_id, version, created_at, is_active, metadata
		FROM cryptographic_keys
		WHERE id = $1
	`

	var key entities.CryptographicKey
	var algorithmStr, usageStr string
	var metadataJSON []byte
	var createdAt time.Time

	err := r.db.QueryRowContext(ctx, query, id).Scan(
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
		&metadataJSON,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New(string(exceptions.ErrKeyNotFound))
	} else if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}

	// Convertir string a KeyAlgorithm
	key.Algorithm = valueobjects.KeyAlgorithm(algorithmStr)
	key.Usage = valueobjects.KeyUsage(usageStr)
	key.CreatedAt = createdAt

	// Convertir metadata de JSONB
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &key.Metadata); err != nil {
			return nil, fmt.Errorf(errFailedToUnmarshalMetadata)
		}
	}

	return &key, nil
}

func (r *postgresKeyRepository) FindByIDAndTenant(ctx context.Context, id, tenantID string) (*entities.CryptographicKey, error) {
	query := `
		SELECT id, name, algorithm, key_size, usage, public_key, key_handle, tenant_id, version, created_at, is_active, metadata
		FROM cryptographic_keys
		WHERE id = $1 AND tenant_id = $2
	`

	var key entities.CryptographicKey
	var algorithmStr, usageStr string
	var metadataJSON []byte
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
		&metadataJSON,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New(string(exceptions.ErrKeyNotFound))
	} else if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}

	key.Algorithm = valueobjects.KeyAlgorithm(algorithmStr)
	key.Usage = valueobjects.KeyUsage(usageStr)
	key.CreatedAt = createdAt

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &key.Metadata); err != nil {
			return nil, fmt.Errorf("%s: %w", errFailedToUnmarshalMetadata, err)
		}
	}

	return &key, nil
}

func (r *postgresKeyRepository) FindByTenant(ctx context.Context, tenantID string) ([]*entities.CryptographicKey, error) {
	query := `
		SELECT id, name, algorithm, key_size, usage, public_key, key_handle, tenant_id, version, created_at, is_active, metadata
		FROM cryptographic_keys
		WHERE tenant_id = $1
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
		var metadataJSON []byte
		var createdAt time.Time

		if err := rows.Scan(
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
			&metadataJSON,
		); err != nil {
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}

		key.Algorithm = valueobjects.KeyAlgorithm(algorithmStr)
		key.Usage = valueobjects.KeyUsage(usageStr)
		key.CreatedAt = createdAt

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &key.Metadata); err != nil {
				return nil, fmt.Errorf(errFailedToUnmarshalMetadata)
			}
		}

		keys = append(keys, &key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return keys, nil
}

func (r *postgresKeyRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM cryptographic_keys WHERE id = $1`

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
