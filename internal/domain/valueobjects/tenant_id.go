package valueobjects

import (
	"errors"
	"github.com/google/uuid"
)

type TenantID struct {
	value string
}

func NewTenantID(value string) (*TenantID, error) {
	if value == "" {
		return nil, errors.New("tenant ID cannot be empty")
	}
	// Validar que sea un UUID válido
	if _, err := uuid.Parse(value); err != nil {
		return nil, errors.New("invalid tenant ID format")
	}
	return &TenantID{value: value}, nil
}

func (t *TenantID) Value() string {
	return t.value
}

func (t *TenantID) Equals(other *TenantID) bool {
	return t.value == other.value
}