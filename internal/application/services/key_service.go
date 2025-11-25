package services

import (
	"context"
	"errors"
	"platform-templates/templates/template-go-gin/internal/domain/entities"
	"platform-templates/templates/template-go-gin/internal/domain/exceptions"
	"platform-templates/templates/template-go-gin/internal/domain/ports/input"
	"platform-templates/templates/template-go-gin/internal/domain/ports/output"
	"platform-templates/templates/template-go-gin/internal/domain/valueobjects"
	"time"

	"github.com/google/uuid"
)

type keyService struct {
	keyRepo     output.KeyRepository
	hsmClient   output.HSMClient
	auditClient output.AuditClient
}

var _ input.KeyManager = (*keyService)(nil)

func NewKeyService(
	keyRepo output.KeyRepository,
	hsmClient output.HSMClient,
	auditClient output.AuditClient,
) input.KeyManager {
	return &keyService{
		keyRepo:     keyRepo,
		hsmClient:   hsmClient,
		auditClient: auditClient,
	}
}

func (s *keyService) CreateKey(ctx context.Context, name string, algorithm valueobjects.KeyAlgorithm, size int, usage entities.KeyUsage, tenantID string) (*entities.CryptographicKey, error) {
	// Validar parámetros de entrada
	if !algorithm.IsValid() {
		return nil, errors.New(string(exceptions.ErrInvalidKeyAlgorithm))
	}

	if !usage.IsValid() {
		return nil, errors.New(string(exceptions.ErrInvalidKeyUsage))
	}

	// Generar par de claves en el HSM
	publicKey, keyHandle, err := s.hsmClient.GenerateKeyPair(ctx, algorithm, size)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=generate_key_pair")
	}

	// Crear entidad de clave
	key := &entities.CryptographicKey{
		ID:        uuid.New().String(),
		Name:      name,
		Algorithm: algorithm,
		KeySize:   size,
		Usage:     usage,
		PublicKey: publicKey,
		KeyHandle: keyHandle,
		TenantID:  tenantID,
		Version:   1,
		CreatedAt: time.Now().UTC(),
		IsActive:  true,
	}

	// Validar entidad
	if err := key.Validate(); err != nil {
		// Rollback: eliminar clave del HSM
		s.hsmClient.DeleteKey(ctx, keyHandle)
		return nil, err
	}

	// Guardar metadata
	if err := s.keyRepo.Save(ctx, key); err != nil {
		// Rollback: eliminar clave del HSM
		s.hsmClient.DeleteKey(ctx, keyHandle)
		return nil, err
	}

	auditEvent := entities.AuditEvent{
		Action:       "KEY_CREATED",
		Actor:        "system", // En producción vendría del JWT
		TenantID:     tenantID,
		ResourceID:   key.ID,
		ResourceType: "CRYPTOGRAPHIC_KEY",
		Details:      map[string]interface{}{"key_name": name, "algorithm": algorithm, "key_size": size},
		Timestamp:    time.Now().UTC(),
	}

	// Auditoría no bloqueante - si falla, no afecta la operación principal
	go func() {
		timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.auditClient.LogSecurityEvent(timeoutCtx, auditEvent); err != nil {
			// Log local del error de auditoría, pero no falla la operación
			// log.Printf("WARNING: Failed to audit key creation: %v", err)
		}
	}()

	return key, nil
}

func (s *keyService) GetKey(ctx context.Context, keyID, tenantID string) (*entities.CryptographicKey, error) {
	key, err := s.keyRepo.FindByIDAndTenant(ctx, keyID, tenantID)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrKeyNotFound))
	}
	return key, nil
}

func (s *keyService) ListKeys(ctx context.Context, tenantID string) ([]*entities.CryptographicKey, error) {
	return s.keyRepo.FindByTenant(ctx, tenantID)
}

func (s *keyService) RotateKey(ctx context.Context, keyID, tenantID string) (*entities.CryptographicKey, error) {
	// Obtener clave existente
	existing, err := s.keyRepo.FindByIDAndTenant(ctx, keyID, tenantID)
	if err != nil {
		return nil, err
	}

	// Crear nueva versión de la clave
	newKey, err := s.CreateKey(ctx, existing.Name+"-rotated", existing.Algorithm, existing.KeySize, existing.Usage, tenantID)
	if err != nil {
		return nil, err
	}

	// Desactivar clave anterior
	existing.Deactivate()
	if err := s.keyRepo.Save(ctx, existing); err != nil {
		// Rollback: eliminar nueva clave
		s.hsmClient.DeleteKey(ctx, newKey.KeyHandle)
		s.keyRepo.Delete(ctx, newKey.ID)
		return nil, err
	}

	return newKey, nil
}

func (s *keyService) DeleteKey(ctx context.Context, keyID, tenantID string) error {
	key, err := s.keyRepo.FindByIDAndTenant(ctx, keyID, tenantID)
	if err != nil {
		return err
	}

	// Eliminar del HSM
	if err := s.hsmClient.DeleteKey(ctx, key.KeyHandle); err != nil {
		return errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=delete_key")
	}

	// Eliminar metadata
	return s.keyRepo.Delete(ctx, keyID)
}
