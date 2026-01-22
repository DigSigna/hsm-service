package entities

import (
	"errors"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/valueobjects"
	"time"
)

type KeyUsage string

const (
	Signing    KeyUsage = "SIGNING"
	Encryption KeyUsage = "ENCRYPTION"
)

type CryptographicKey struct {
	ID               string                    `json:"id"`
	TenantID         string                    `json:"tenant_id"`
	OwnerType        valueobjects.OwnerType    `json:"owner_type"`
	OwnerID          string                    `json:"owner_id"`
	ParentKeyID      *string                   `json:"parent_key_id,omitempty"`
	CertLevel        int                       `json:"cert_level,omitempty"`
	Name             string                    `json:"name"`
	Alias            string                    `json:"alias"`
	Algorithm        valueobjects.KeyAlgorithm `json:"algorithm"`
	KeySize          int                       `json:"key_size"`
	Purpose          valueobjects.KeyUsage     `json:"purpose"`
	PublicKey        []byte                    `json:"public_key"`
	KeyHandle        string                    `json:"key_handle"`
	KeyLabel         string                    `json:"key_label"`
	IsHardwareBacked bool                      `json:"is_hardware_backed"`
	HSMSlot          int                       `json:"hsm_slot"`
	IsActive         bool                      `json:"is_active"`
	Version          int                       `json:"version"`
	RotationDate     time.Time                 `json:"rotation_date,omitempty"`
	ExpirationDate   time.Time                 `json:"expiration_date,omitempty"`
	CreatedAt        time.Time                 `json:"created_at"`
	Metadata         map[string]string         `json:"metadata,omitempty"`
}

func (k *CryptographicKey) Validate() error {
	if k.Name == "" {
		return errors.New(string(exceptions.ErrInvalidKeyName))
	}
	if !k.Algorithm.IsValid() {
		return errors.New(string(exceptions.ErrInvalidAlgorithm))
	}
	if !k.isValidKeySize() {
		return errors.New(string(exceptions.ErrInvalidKeySize))
	}
	if k.TenantID == "" {
		return errors.New(string(exceptions.ErrInvalidTenant))
	}
	if !k.Purpose.IsValid() {
		return errors.New(string(exceptions.ErrInvalidKeyUsage))
	}
	return nil
}

func (k *CryptographicKey) isValidKeySize() bool {
	sizes := map[valueobjects.KeyAlgorithm][]int{
		valueobjects.RSA:     {2048, 3072, 4096},
		valueobjects.ECDSA:   {256, 384, 521},
		valueobjects.Ed25519: {256},
	}

	validSizes, exists := sizes[k.Algorithm]
	if !exists {
		return false
	}

	for _, size := range validSizes {
		if k.KeySize == size {
			return true
		}
	}
	return false
}

func (k *CryptographicKey) Deactivate() {
	k.IsActive = false
}
