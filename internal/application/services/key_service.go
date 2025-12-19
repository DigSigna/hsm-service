package services

import (
	"context"
	"errors"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"

	"time"

	"github.com/google/uuid"
)

type keyService struct {
	keyRepo         output.KeyRepository
	hsmManager      output.HSMManager
	auditDispatcher output.AuditEventDispatcher
	tenantRepo      output.TenantRepository
}

type contextKey string

const (
	tenantErrorMsg            = "error checking tenant existence"
	tenantIDKey    contextKey = "tenant_id"
)

var _ input.KeyManager = (*keyService)(nil)

func NewKeyService(
	keyRepo output.KeyRepository,
	hsmManager output.HSMManager,
	auditDispatcher output.AuditEventDispatcher,
	tenantRepo output.TenantRepository,
) input.KeyManager {
	return &keyService{
		keyRepo:         keyRepo,
		hsmManager:      hsmManager,
		auditDispatcher: auditDispatcher,
		tenantRepo:      tenantRepo,
	}
}

func (s *keyService) CreateKey(ctx context.Context, name string, algorithm valueobjects.KeyAlgorithm, size int, usage valueobjects.KeyUsage, tenantID string) (key *entities.CryptographicKey, err error) {
	ctx = context.WithValue(ctx, tenantIDKey, tenantID)

	start := time.Now()

	defer func() {
		data := valueobjects.AuditData{
			ServiceName: KeyServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "CREATE_KEY",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			Metadata: map[string]interface{}{
				"key_name":  name,
				"algorithm": algorithm,
				"key_size":  size,
				"usage":     usage,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data)
		}
	}()

	// Validar parámetros de entrada
	if !algorithm.IsValid() {
		return nil, errors.New(string(exceptions.ErrInvalidKeyAlgorithm))
	}

	if !usage.IsValid() {
		return nil, errors.New(string(exceptions.ErrInvalidKeyUsage))
	}

	// validar tenant
	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)

	if err != nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}

	keyLabel := fmt.Sprintf("%s_%s_%s", tenantID, name, uuid.New().String()[:8])

	publicKey, keyHandle, err := s.hsmManager.GenerateKeyPair(
		ctx,
		algorithm,
		size,
		keyLabel,
		tenant.HSMSlot)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=generate_key_pair")
	}

	// Crear entidad de clave
	key = &entities.CryptographicKey{
		TenantID:  tenantID,
		Name:      name,
		Alias:     keyLabel,
		Algorithm: algorithm,
		KeySize:   size,
		Usage:     usage,
		PublicKey: publicKey,
		KeyHandle: keyHandle,
		KeyLabel:  keyLabel,
		// Asumir que todas las claves generadas son hardware-backed
		IsHardwareBacked: true,
		HSMSlot:          tenant.HSMSlot,
		Version:          1,
		ExpirationDate:   time.Now().Add(365 * 24 * time.Hour), // 1 año por defecto
		IsActive:         true,
	}

	// Validar entidad
	if err := key.Validate(); err != nil {
		// Rollback: eliminar clave del HSM
		s.hsmManager.DeleteKey(ctx, keyHandle, tenant.HSMSlot)
		return nil, err
	}

	// Guardar metadata
	if err := s.keyRepo.Save(ctx, key); err != nil {
		// Rollback: eliminar clave del HSM
		s.hsmManager.DeleteKey(ctx, keyHandle, tenant.HSMSlot)
		return nil, err
	}

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

func (s *keyService) RotateKey(ctx context.Context, keyID, tenantID string) (newKey *entities.CryptographicKey, err error) {
	start := time.Now()

	defer func() {
		data := valueobjects.AuditData{
			ServiceName: KeyServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "ROTATE_KEY",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			Metadata: map[string]interface{}{
				"key_id": keyID,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data)
		}
	}()

	// Obtener clave existente
	existing, err := s.keyRepo.FindByIDAndTenant(ctx, keyID, tenantID)
	if err != nil {
		return nil, err
	}

	// Crear nueva versión de la clave
	newKey, err = s.CreateKey(ctx, existing.Name+"-rotated", existing.Algorithm, existing.KeySize, existing.Usage, tenantID)
	if err != nil {
		return nil, err
	}

	// validar tenant
	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)

	if err != nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}

	// Desactivar clave anterior
	existing.Deactivate()
	if err := s.keyRepo.Save(ctx, existing); err != nil {
		// Rollback: eliminar nueva clave
		s.hsmManager.DeleteKey(ctx, newKey.KeyHandle, tenant.HSMSlot)
		s.keyRepo.Delete(ctx, newKey.ID)
		return nil, err
	}

	return newKey, nil
}

func (s *keyService) DeleteKey(ctx context.Context, keyID, tenantID string) (err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: KeyServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "DELETE_KEY",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			Metadata: map[string]interface{}{
				"key_id": keyID,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data)
		}
	}()

	// Obtener clave
	key, err := s.keyRepo.FindByIDAndTenant(ctx, keyID, tenantID)
	if err != nil {
		return err
	}

	// validar tenant
	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)

	if err != nil {
		return exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}

	// Eliminar del HSM
	if err := s.hsmManager.DeleteKey(ctx, key.KeyHandle, tenant.HSMSlot); err != nil {
		return errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=delete_key")
	}

	// Eliminar metadata
	return s.keyRepo.Delete(ctx, keyID)
}
