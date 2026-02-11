package valueobjects

import (
	"hsm-service/internal/domain/exceptions"
)

// IdentityContext representa el contexto de identidad del actor
type IdentityContext struct {
	TenantID          string
	OwnerType         OwnerType
	OwnerID           string
	OrganizationID    *string
	ParentKeyID       *string
	UserID            string
	CertLevel         int
	MaxCertLevel      int
	CanCertify        bool
	CertificationPath string
	Permissions       map[string]interface{}
}

// Validate valida el contexto de identidad
func (i *IdentityContext) Validate() error {
	if i.TenantID == "" {
		return exceptions.DomainErrTenantRequired
	}
	if i.OwnerID == "" {
		return exceptions.DomainErrOwnerIdRequired
	}
	if !i.OwnerType.IsValid() {
		return exceptions.DomainErrInvalidOwnerType
	}
	return nil
}

// CanCertifyLevel valida si puede certificar un nivel específico
func (i *IdentityContext) CanCertifyLevel(level int) bool {
	return i.CanCertify && i.MaxCertLevel >= level
}
