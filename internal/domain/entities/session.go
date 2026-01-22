package entities

import (
	"hsm-service/internal/domain/valueobjects"
	"time"
)

type Session struct {
	ID                string                 `json:"id"`
	TenantID          string                 `json:"tenant_id"`
	OwnerType         valueobjects.OwnerType `json:"owner_type"`
	OwnerID           string                 `json:"owner_id"`
	OrganizationID    *string                `json:"organization_id,omitempty"`
	ParentKeyID       *string                `json:"parent_key_id,omitempty"`
	CertLevel         int                    `json:"cert_level"`
	CertificationPath string                 `json:"certification_path"`
	CanCertify        bool                   `json:"can_certify"`
	MaxCertLevel      int                    `json:"max_cert_level"`
	Permissions       map[string]interface{} `json:"permissions"`
	UserID            string                 `json:"user_id"`
	CreatedAt         time.Time              `json:"created_at"`
	ExpiresAt         time.Time              `json:"expires_at"`
	IsActive          bool                   `json:"is_active"`
	TokenID           string                 `json:"token_id"`
}

func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

func (s *Session) HasPermission(permission string) bool {
	for _, p := range s.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}
