package entities

import "time"

type HSMSlot struct {
	ID                string                 `json:"id,omitempty"`
	Label             string                 `json:"label"`
	SlotNumber        uint                   `json:"slot_number"`
	IsTemporaryID     bool                   `json:"is_temporary_id"`
	PIN_IV            []byte                 `json:"pin_iv,omitempty"`
	Pin_ciphertext    []byte                 `json:"pin_ciphertext,omitempty"`
	Pin_auth_tag      []byte                 `json:"pin_auth_tag,omitempty"`
	KeyMetadataID     string                 `json:"key_metadata_id"`
	EncryptionContext map[string]interface{} `json:"encryption_context,omitempty"`
	CreatedAt         time.Time              `json:"created_at,omitempty"`
	UpdatedAt         time.Time              `json:"updated_at,omitempty"`
}
