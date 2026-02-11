package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/output"
	"time"
)

type MySQLSlotStorage struct {
	db *sql.DB
}

var _ output.SlotRepository = (*MySQLSlotStorage)(nil)

func NewMySQLSlotStorage(db *sql.DB) output.SlotRepository {
	return &MySQLSlotStorage{db: db}
}

// CreateSlot implements [output.SlotRepository].
func (m *MySQLSlotStorage) CreateSlot(ctx context.Context, slot entities.HSMSlot) error {
	query := `
		INSERT INTO hsm_slots (
			id,
			label,			
			slot_number,
			pin_iv,
			pin_ciphertext,
			pin_auth_tag,
			key_metadata_id,
			encryption_context
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	encryptionContext, errj := json.Marshal(slot.EncryptionContext)
	if errj != nil {
		return fmt.Errorf("failed to marshal metadata: %w", errj)
	}

	_, err := m.db.ExecContext(ctx, query,
		slot.ID,
		slot.Label,
		slot.SlotNumber,
		slot.PIN_IV,
		slot.Pin_ciphertext,
		slot.Pin_auth_tag,
		nil,
		string(encryptionContext),
	)

	if err != nil {
		return fmt.Errorf("failed to create HSM slot: %w", err)
	}

	return nil
}

// DeleteSlot implements [output.SlotRepository].
func (m *MySQLSlotStorage) DeleteSlot(ctx context.Context, id string) error {
	sql := `DELETE FROM hsm_slots WHERE id = ?`

	_, err := m.db.ExecContext(ctx, sql, id)
	if err != nil {
		return fmt.Errorf("failed to delete HSM slot: %w", err)
	}

	return nil
}

// GetAllSlots implements [output.SlotRepository].
func (m *MySQLSlotStorage) GetAllSlots(ctx context.Context) ([]*entities.HSMSlot, error) {
	query := `SELECT id, label, slot_number, is_temporary_id, pin_iv,
		pin_ciphertext, pin_auth_tag, key_metadata_id, created_at, updated_at
		FROM hsm_slots`

	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get HSM slots: %w", err)
	}
	defer rows.Close()

	var slots []*entities.HSMSlot
	var createdAt time.Time
	var updatedAt time.Time

	for rows.Next() {
		var slot entities.HSMSlot
		if err := rows.Scan(
			&slot.ID,
			&slot.Label,
			&slot.SlotNumber,
			&slot.IsTemporaryID,
			&slot.PIN_IV,
			&slot.Pin_ciphertext,
			&slot.Pin_auth_tag,
			&slot.KeyMetadataID,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan HSM slot: %w", err)
		}

		slot.CreatedAt = createdAt
		slot.UpdatedAt = updatedAt

		slots = append(slots, &slot)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return slots, nil
}

// GetSlotByID implements [output.SlotRepository].
func (m *MySQLSlotStorage) GetSlotByID(ctx context.Context, id string) (*entities.HSMSlot, error) {
	query := `
		SELECT id, label, slot_number, is_temporary_id,
		pin_iv, pin_ciphertext, pin_auth_tag, key_metadata_id, created_at, updated_at
		FROM hsm_slots
		WHERE id = ?`

	var slot entities.HSMSlot
	var createdAt time.Time
	var updatedAt time.Time
	err := m.db.QueryRowContext(ctx, query, id).Scan(
		&slot.ID,
		&slot.Label,
		&slot.SlotNumber,
		&slot.IsTemporaryID,
		&slot.PIN_IV,
		&slot.Pin_ciphertext,
		&slot.Pin_auth_tag,
		&slot.KeyMetadataID,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get HSM slot by ID: %w", err)
	}

	slot.CreatedAt = createdAt
	slot.UpdatedAt = updatedAt

	return &slot, nil
}

// UpdateSlot implements [output.SlotRepository].
func (m *MySQLSlotStorage) UpdateSlot(ctx context.Context, slot entities.HSMSlot) error {
	query := `
		UPDATE hsm_slots
		SET label = ?, slot_number = ?, key_metadata_id = ?
		WHERE id = ?`

	_, err := m.db.ExecContext(ctx, query,
		slot.Label,
		slot.SlotNumber,
		slot.KeyMetadataID,
		slot.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update HSM slot: %w", err)
	}

	return nil
}

// GetSlotsWithTemporaryIDs implements [output.SlotRepository].
func (m *MySQLSlotStorage) GetSlotsWithTemporaryIDs(ctx context.Context) ([]*entities.HSMSlot, error) {
	query := `
		SELECT id, label, slot_number, pin_iv,
		pin_ciphertext, pin_auth_tag, key_metadata_id, created_at, updated_at
		FROM hsm_slots
		WHERE is_temporary = true`

	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get HSM slots with temporary IDs: %w", err)
	}

	defer rows.Close()

	var slots []*entities.HSMSlot
	var createdAt time.Time
	var updatedAt time.Time

	for rows.Next() {
		var slot entities.HSMSlot
		if err := rows.Scan(
			&slot.ID,
			&slot.Label,
			&slot.SlotNumber,
			&slot.PIN_IV,
			&slot.Pin_ciphertext,
			&slot.Pin_auth_tag,
			&slot.KeyMetadataID,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan HSM slot: %w", err)
		}

		slot.CreatedAt = createdAt
		slot.UpdatedAt = updatedAt

		slots = append(slots, &slot)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return slots, nil
}

// UpdateSlotNumber implements [output.SlotRepository].
func (m *MySQLSlotStorage) UpdateSlotNumber(ctx context.Context, slotID string, slotNumber uint) error {
	query := `
		UPDATE hsm_slots
		SET slot_number = ?, is_temporary_id = ?
		WHERE id = ?`

	_, err := m.db.ExecContext(ctx, query,
		slotNumber,
		false, // is_temporary_id = false since we are updating with the real slot number
		slotID,
	)
	if err != nil {
		return fmt.Errorf("failed to update HSM slot: %w", err)
	}

	return nil
}
