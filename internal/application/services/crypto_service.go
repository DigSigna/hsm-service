package services

import (
	"context"
	"crypto/sha256"
	"errors"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"time"
)

type cryptoService struct {
	hsmManager      output.HSMManager
	keyRepo         output.KeyRepository
	tenantRepo      output.TenantRepository
	auditDispatcher output.AuditEventDispatcher
}

var _ input.CryptoService = (*cryptoService)(nil)

func NewCryptoService(
	hsmManager output.HSMManager,
	keyRepo output.KeyRepository,
	tenantRepo output.TenantRepository,
	auditDispatcher output.AuditEventDispatcher,
) input.CryptoService {
	return &cryptoService{
		hsmManager:      hsmManager,
		keyRepo:         keyRepo,
		tenantRepo:      tenantRepo,
		auditDispatcher: auditDispatcher,
	}
}

// Método auxiliar para obtener clave HSM por label y tenant
func (s *cryptoService) getHSMKeyByLabel(ctx context.Context, label, tenantID string) (*entities.HSMKey, error) {
	// validar tenant
	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)

	if err != nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}

	// Listar todas las claves y filtrar por tenant y label
	allKeys, err := s.hsmManager.ListKeys(ctx, tenant.HSMSlot)
	if err != nil {
		return nil, err
	}

	for _, key := range allKeys {
		if key.Label == label && key.TenantID == tenantID {
			return key, nil
		}
	}
	return nil, errors.New(string(exceptions.ErrKeyNotFound))
}

func (s *cryptoService) SignData(ctx context.Context, keyLabel string, data []byte, tenantID string) (signature []byte, err error) {
	start := time.Now()
	defer func() {

		auditData := valueobjects.AuditData{
			ServiceName: CryptoServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "SIGN_DATA",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			ActorType:   "SERVICE",
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata: map[string]interface{}{
				"label": keyLabel,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, auditData, nil)
		}
	}()

	// Obtener la clave HSM
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return nil, err
	}

	// Validar que la clave puede firmar
	if hsmKey.Usage != valueobjects.KeyUsageSigning && hsmKey.Usage != valueobjects.KeyUsageBoth {
		return nil, errors.New(string(exceptions.ErrInvalidKeyUsage))
	}

	// Hashear datos
	hash := sha256.Sum256(data)

	// validar tenant
	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)

	if err != nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}
	// Firmar el hash usando HSM
	signature, err = s.hsmManager.SignHash(ctx, hsmKey.KeyHandle, hash[:], tenant.HSMSlot)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=sign_data")
	}

	return signature, nil
}

func (s *cryptoService) VerifySignature(ctx context.Context, keyLabel string, data, signature []byte, tenantID string) (valid bool, err error) {
	start := time.Now()
	defer func() {

		auditData := valueobjects.AuditData{
			ServiceName: CryptoServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "VERIFY_SIGNATURE",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			ActorType:   "SERVICE",
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata: map[string]interface{}{
				"label": keyLabel,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, auditData, nil)
		}
	}()

	// Obtener la clave HSM
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return false, err
	}

	// Validar que la clave puede verificar
	if hsmKey.Usage != valueobjects.KeyUsageSigning && hsmKey.Usage != valueobjects.KeyUsageBoth {
		return false, errors.New(string(exceptions.ErrInvalidKeyUsage))
	}

	// Hashear datos
	hash := sha256.Sum256(data)

	// validar tenant
	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)

	if err != nil {
		return false, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}
	// Verificar firma usando HSM
	valid, err = s.hsmManager.VerifySignature(ctx, hsmKey.KeyHandle, hash[:], signature, tenant.HSMSlot)
	if err != nil {
		return false, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=verify_signature")
	}

	return valid, nil
}

func (s *cryptoService) EncryptData(ctx context.Context, keyLabel string, plaintext []byte, tenantID string) (ciphertext []byte, err error) {
	start := time.Now()
	defer func() {

		data := valueobjects.AuditData{
			ServiceName: CryptoServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "ENCRYPT_DATA",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			ActorType:   "SERVICE",
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata: map[string]interface{}{
				"label": keyLabel,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()

	// Obtener la clave HSM
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return nil, err
	}

	// Validar que la clave puede encriptar
	if hsmKey.Usage != valueobjects.KeyUsageEncryption && hsmKey.Usage != valueobjects.KeyUsageBoth {
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

	// Encriptar datos usando HSM
	ciphertext, err = s.hsmManager.Encrypt(ctx, hsmKey.KeyHandle, plaintext, tenant.HSMSlot)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=encrypt")
	}

	return ciphertext, nil
}

func (s *cryptoService) DecryptData(ctx context.Context, keyLabel string, ciphertext []byte, tenantID string) (plaintext []byte, err error) {
	start := time.Now()
	defer func() {

		data := valueobjects.AuditData{
			ServiceName: CryptoServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "DECRYPT_DATA",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			ActorType:   "SERVICE",
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata: map[string]interface{}{
				"label": keyLabel,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()
	// Obtener la clave HSM
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return nil, err
	}

	// Validar que la clave puede desencriptar
	if hsmKey.Usage != valueobjects.KeyUsageEncryption && hsmKey.Usage != valueobjects.KeyUsageBoth {
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

	// Desencriptar datos usando HSM
	plaintext, err = s.hsmManager.Decrypt(ctx, hsmKey.KeyHandle, ciphertext, tenant.HSMSlot)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=decrypt")
	}

	return plaintext, nil
}

func (s *cryptoService) SignHash(ctx context.Context, keyLabel string, hash []byte, tenantID string) (signature []byte, err error) {
	start := time.Now()
	defer func() {

		data := valueobjects.AuditData{
			ServiceName: CryptoServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "SIGN_HASH",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			ActorType:   "SERVICE",
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata: map[string]interface{}{
				"label": keyLabel,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()

	// Obtener la clave HSM
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return nil, err
	}

	// Validar que la clave puede firmar
	if hsmKey.Usage != valueobjects.KeyUsageSigning && hsmKey.Usage != valueobjects.KeyUsageBoth {
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
	// Firmar el hash directamente usando HSM
	signature, err = s.hsmManager.SignHash(ctx, hsmKey.KeyHandle, hash, tenant.HSMSlot)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=sign_hash")
	}

	return signature, nil
}

func (s *cryptoService) VerifyHashSignature(ctx context.Context, keyLabel string, hash, signature []byte, tenantID string) (valid bool, err error) {
	start := time.Now()
	defer func() {

		data := valueobjects.AuditData{
			ServiceName: CryptoServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "VERIFY_HASH_SIGNATURE",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			ActorType:   "SERVICE",
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata: map[string]interface{}{
				"label": keyLabel,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()
	// Obtener la clave HSM
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return false, err
	}

	// Validar que la clave puede verificar
	if hsmKey.Usage != valueobjects.KeyUsageSigning && hsmKey.Usage != valueobjects.KeyUsageBoth {
		return false, errors.New(string(exceptions.ErrInvalidKeyUsage))
	}

	// validar tenant
	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)

	if err != nil {
		return false, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}
	// Verificar firma del hash usando HSM
	valid, err = s.hsmManager.VerifySignature(ctx, hsmKey.KeyHandle, hash, signature, tenant.HSMSlot)
	if err != nil {
		return false, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=verify_hash_signature")
	}
	return valid, nil
}
