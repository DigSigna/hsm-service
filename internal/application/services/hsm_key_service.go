package services

import (
	"context"
	"errors"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"time"
)

type HSMKeyService struct {
	keyRepo         output.KeyRepository
	hsmManager      output.HSMManager
	auditDispatcher output.AuditEventDispatcher
	tenantRepo      output.TenantRepository
}

var _ input.HSMKeyManager = (*HSMKeyService)(nil)

func NewHSMKeyService(
	keyRepo output.KeyRepository,
	hsmManager output.HSMManager,
	auditDispatcher output.AuditEventDispatcher,
	tenantRepo output.TenantRepository,
) input.HSMKeyManager {
	return &HSMKeyService{
		keyRepo:         keyRepo,
		hsmManager:      hsmManager,
		auditDispatcher: auditDispatcher,
		tenantRepo:      tenantRepo,
	}
}

func (s *HSMKeyService) CreateHSMKey(ctx context.Context, label string, algorithm valueobjects.KeyAlgorithm, size int, tenantID string) (hsmKey *entities.HSMKey, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: HSMKeyServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "CREATE_HSM_KEY",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			Metadata: map[string]interface{}{
				"label":     label,
				"algorithm": algorithm.String(),
				"size":      size,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data)
		}
	}()

	// validar tenant
	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)

	if err != nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}

	// Generar clave en HSM
	publicKey, keyHandle, err := s.hsmManager.GenerateKeyPair(ctx, algorithm, size, label, tenant.HSMSlot)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=generate_key_pair")
	}

	hsmKey = &entities.HSMKey{
		Label:     label,
		Type:      valueobjects.KeyType(algorithm), // Convertir algoritmo a tipo
		Size:      uint32(size),
		TenantID:  tenantID,
		PublicKey: publicKey,
		KeyHandle: keyHandle,
		CreatedAt: time.Now().UTC(),
		IsActive:  true,
		Usage:     valueobjects.KeyUsageBoth, // O determinar según el contexto
	}
	return hsmKey, nil
}

func (s *HSMKeyService) ListHSMKeys(ctx context.Context, tenantID string) (tenantKeys []*entities.HSMKey, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: HSMKeyServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "LIST_HSM_KEYS",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data)
		}
	}()
	// validar tenant
	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)

	if err != nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}

	// Listar todas las claves y filtrar por tenant
	allKeys, err := s.hsmManager.ListKeys(ctx, tenant.HSMSlot)
	if err != nil {
		return nil, err
	}

	for _, key := range allKeys {
		if key.TenantID == tenantID {
			tenantKeys = append(tenantKeys, key)
		}
	}

	return tenantKeys, nil
}
func (s *HSMKeyService) GetHSMPublicKey(ctx context.Context, keyLabel, tenantID string) (publicKey []byte, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: HSMKeyServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "GET_HSM_PUBLIC_KEY",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data)
		}
	}()
	// validar tenant
	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)

	if err != nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}

	// Buscar la clave por label y tenant
	allKeys, err := s.hsmManager.ListKeys(ctx, tenant.HSMSlot)
	if err != nil {
		return nil, err
	}

	for _, key := range allKeys {
		if key.Label == keyLabel && key.TenantID == tenantID {
			return key.PublicKey, nil
		}
	}

	return nil, errors.New(string(exceptions.ErrKeyNotFound))
}
