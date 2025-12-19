package entities

import "time"

type Tenant struct {
	ID           string
	Name         string
	ContactEmail string
	PlanType     PlanType
	Status       TenantStatus
	Config       map[string]interface{}
	HSMSlot      int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type TenantStatus string
type PlanType string

const (
	TenantActive    TenantStatus = "active"
	TenantSuspended TenantStatus = "suspended"
)

const (
	PlanFree       PlanType = "free"
	PlanBasic      PlanType = "basic"
	PlanPremium    PlanType = "premium"
	PlanEnterprise PlanType = "enterprise"
)
