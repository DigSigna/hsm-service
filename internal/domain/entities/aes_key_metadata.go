package entities

import "time"

type AESKeyMetadata struct {
	ID                string     `json:"id,omitempty"`
	HSMSlotID         string     `json:"hsm_slot_id,omitempty"`
	VersionID         string     `json:"version_id"`
	Active            bool       `json:"active"`
	Algorithm         string     `json:"algorithm"`
	Source            string     `json:"source"`
	Description       string     `json:"description"`
	WrappedDataKey    []byte     `json:"wrapped_data_key,omitempty"`
	WrappedKeyVersion string     `json:"wrapped_key_version,omitempty"`
	LastRewrapAt      *time.Time `json:"last_wrapped_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at,omitempty"`
	UpdatedAt         time.Time  `json:"updated_at,omitempty"`
}
