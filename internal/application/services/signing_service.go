package services

import (
	"context"
	"errors"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"time"
)

type signingService struct {
	keyRepo         output.KeyRepository
	hsmManager      output.HSMManager
	auditDispatcher output.AuditEventDispatcher
	tenantRepo      output.TenantRepository
}

var _ input.Signer = (*signingService)(nil)

func NewSigningService(
	keyRepo output.KeyRepository,
	hsmManager output.HSMManager,
	auditDispatcher output.AuditEventDispatcher,
	tenantRepo output.TenantRepository,
) input.Signer {
	return &signingService{
		keyRepo:         keyRepo,
		hsmManager:      hsmManager,
		auditDispatcher: auditDispatcher,
		tenantRepo:      tenantRepo,
	}
}

func (s *signingService) SignHash(ctx context.Context, keyID string, hash []byte, tenantID string) (signature []byte, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: SigningServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "SIGN_HASH",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			Metadata: map[string]interface{}{
				"key_id":      keyID,
				"hash_length": len(hash),
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data)
		}
	}()
	// Validar que la clave existe y pertenece al tenant
	key, err := s.keyRepo.FindByIDAndTenant(ctx, keyID, tenantID)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrKeyNotFound))
	}

	if !key.IsActive {
		return nil, errors.New(string(exceptions.ErrKeyInactive))
	}

	if key.Usage != valueobjects.KeyUsageSigning && key.Usage != valueobjects.KeyUsageBoth {
		return nil, errors.New(string(exceptions.ErrInvalidKeyUsage))
	}

	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)

	if err != nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}

	// Firmar el hash usando el HSM
	signature, err = s.hsmManager.SignHash(ctx, key.KeyHandle, hash, tenant.HSMSlot)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=sign_hash")
	}

	return signature, nil
}

func (s *signingService) GetPublicKey(ctx context.Context, keyID, tenantID string) (publicKey []byte, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: SigningServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "GET_PUBLIC_KEY",
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

	key, err := s.keyRepo.FindByID(ctx, keyID)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrKeyNotFound))
	}

	return key.PublicKey, nil
}
