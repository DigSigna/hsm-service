package entities

import "time"

type Tenant struct {
	ID        string
	Name      string
	Status    TenantStatus
	CreatedAt time.Time
}

type TenantStatus string

const (
	TenantActive    TenantStatus = "active"
	TenantSuspended TenantStatus = "suspended"
)
