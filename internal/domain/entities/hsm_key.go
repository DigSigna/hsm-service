package entities

import (
	"hsm-service/internal/domain/valueobjects"
	"time"
)

type HSMKey struct {
	Label     string                `json:"label"`
	Type      valueobjects.KeyType  `json:"type"`
	Size      uint32                `json:"size"`
	TenantID  string                `json:"tenant_id"`
	PublicKey []byte                `json:"public_key"`
	KeyHandle string                `json:"key_handle"`
	CreatedAt time.Time             `json:"created_at"`
	IsActive  bool                  `json:"is_active"`
	Usage     valueobjects.KeyUsage `json:"usage"`
}
