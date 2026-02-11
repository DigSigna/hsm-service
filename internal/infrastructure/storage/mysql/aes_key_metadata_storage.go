package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/output"
	"time"
)

type MySQLAESKeyMetadataStorage struct {
	db *sql.DB
}

var _ output.AESKeyMetadataRepository = (*MySQLAESKeyMetadataStorage)(nil)

func NewMySQLAESKeyMetadataStorage(db *sql.DB) output.AESKeyMetadataRepository {
	return &MySQLAESKeyMetadataStorage{db: db}
}

// CreateMetadata implements [output.AESKeyMetadataRepository].
func (m *MySQLAESKeyMetadataStorage) CreateMetadata(ctx context.Context, metadata entities.AESKeyMetadata) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "SET @skip_aes_triggers = 1")
	if err != nil {
		return fmt.Errorf("failed to set skip flag: %w", err)
	}

	query := `		
		INSERT INTO aes_key_metadata (
			id,
			hsm_slot_id,
			version_id,
			active,
			algorithm,
			source,
			description,
			wrapped_data_key,
			wrap_key_version,
			last_rewrap_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = tx.ExecContext(ctx, query,
		metadata.ID,
		metadata.HSMSlotID,
		metadata.VersionID,
		metadata.Active,
		metadata.Algorithm,
		metadata.Source,
		metadata.Description,
		metadata.WrappedDataKey,
		metadata.WrappedKeyVersion,
		metadata.LastRewrapAt,
	)

	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE hsm_slots SET key_metadata_id = ? WHERE id = ?
	`, metadata.ID, metadata.HSMSlotID)
	if err != nil {
		return fmt.Errorf("failed to update hsm_slot with metadata_id: %w", err)
	}

	_, err = tx.ExecContext(ctx, "SET @skip_aes_triggers = 0")
	if err != nil {
		return fmt.Errorf("failed to reset skip flag: %w", err)
	}

	// Commit
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteMetadata implements [output.AESKeyMetadataRepository].
func (m *MySQLAESKeyMetadataStorage) DeleteMetadata(ctx context.Context, id string) error {
	sql := `DELETE FROM aes_key_metadata WHERE id = ?`

	_, err := m.db.ExecContext(ctx, sql, id)

	if err != nil {
		return err
	}

	return nil
}

// GetAllMetadata implements [output.AESKeyMetadataRepository].
func (m *MySQLAESKeyMetadataStorage) GetAllMetadata(ctx context.Context) ([]entities.AESKeyMetadata, error) {
	query := `
		SELECT
			id,
			hsm_slot_id,
			version_id,
			active,
			algorithm,
			source,
			description,
			wrapped_data_key,
			wrap_key_version,
			last_rewrap_at,
			created_at,
			updated_at
		FROM aes_key_metadata
	`

	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var metadataList []entities.AESKeyMetadata
	var createdAt, updatedAt time.Time
	var lastRewrapAt *time.Time
	for rows.Next() {
		var metadata entities.AESKeyMetadata
		if err := rows.Scan(
			&metadata.ID,
			&metadata.HSMSlotID,
			&metadata.VersionID,
			&metadata.Active,
			&metadata.Algorithm,
			&metadata.Source,
			&metadata.Description,
			&metadata.WrappedDataKey,
			&metadata.WrappedKeyVersion,
			&lastRewrapAt,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		metadata.LastRewrapAt = lastRewrapAt
		metadata.CreatedAt = createdAt
		metadata.UpdatedAt = updatedAt
		metadataList = append(metadataList, metadata)
	}

	return metadataList, nil
}

// GetMetadataByID implements [output.AESKeyMetadataRepository].
func (m *MySQLAESKeyMetadataStorage) GetMetadataByID(ctx context.Context, id string) (*entities.AESKeyMetadata, error) {
	query := `
		SELECT
			id,
			hsm_slot_id,
			version_id,
			active,
			algorithm,
			source,
			description,
			wrapped_data_key,
			wrap_key_version,
			last_rewrap_at,
			created_at,
			updated_at
		FROM aes_key_metadata
		WHERE id = ?
	`

	row := m.db.QueryRowContext(ctx, query, id)

	var metadata entities.AESKeyMetadata
	var createdAt, updatedAt time.Time
	var lastRewrapAt *time.Time

	if err := row.Scan(
		&metadata.ID,
		&metadata.HSMSlotID,
		&metadata.VersionID,
		&metadata.Active,
		&metadata.Algorithm,
		&metadata.Source,
		&metadata.Description,
		&metadata.WrappedDataKey,
		&metadata.WrappedKeyVersion,
		&lastRewrapAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}

	metadata.CreatedAt = createdAt
	metadata.UpdatedAt = updatedAt
	metadata.LastRewrapAt = lastRewrapAt

	return &metadata, nil
}

// DisableMetadata implements [output.AESKeyMetadataRepository].
func (m *MySQLAESKeyMetadataStorage) DisableMetadata(ctx context.Context, id string) error {
	query := `
		UPDATE aes_key_metadata
		SET active = FALSE
		WHERE id = ?
	`
	_, err := m.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	return nil
}
