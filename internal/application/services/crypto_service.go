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
	"hsm-service/pkg/helpers"
	"time"
)

const (
	slotErrorMsg = "error checking slot existence"
)

type cryptoService struct {
	hsmManager      output.HSMManager
	keyRepo         output.KeyRepository
	tenantRepo      output.TenantRepository
	auditDispatcher output.AuditEventDispatcher
	slotRepo        output.SlotRepository
}

var _ input.CryptoService = (*cryptoService)(nil)

// cryptoOperationContext holds information for crypto operations
type cryptoOperationContext struct {
	keyLabel  string
	tenantID  string
	operation string
	start     time.Time
}

func NewCryptoService(
	hsmManager output.HSMManager,
	keyRepo output.KeyRepository,
	tenantRepo output.TenantRepository,
	auditDispatcher output.AuditEventDispatcher,
	slotRepo output.SlotRepository,
) input.CryptoService {
	return &cryptoService{
		hsmManager:      hsmManager,
		keyRepo:         keyRepo,
		tenantRepo:      tenantRepo,
		auditDispatcher: auditDispatcher,
		slotRepo:        slotRepo,
	}
}

// validateKeyUsageForOperation validates that a key can be used for a specific operation
func (s *cryptoService) validateKeyUsageForOperation(
	hsmKey *entities.HSMKey,
	requiredUsage valueobjects.KeyUsage) error {

	if hsmKey.Usage != requiredUsage && hsmKey.Usage != valueobjects.KeyUsageBoth {
		return errors.New(string(exceptions.ErrInvalidKeyUsage))
	}
	return nil
}

// getSlotForTenant retrieves the HSM slot for a given tenant
func (s *cryptoService) getSlotForTenant(ctx context.Context, tenantID string) (*entities.HSMSlot, error) {
	// Validate tenant
	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)
	if err != nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}

	// Get slot
	slot, err := getSlotWithAudit(ctx, *tenant.HSMSlotID, s.slotRepo, s.auditDispatcher)
	if err != nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrSlotNotFound,
			slotErrorMsg,
		).WithDetail("original_error", err.Error())
	}

	return slot, nil
}

// auditCryptoOperation performs audit logging for crypto operations
func (s *cryptoService) auditCryptoOperation(
	ctx context.Context,
	err *error,
	opCtx *cryptoOperationContext) {

	data := valueobjects.AuditData{
		ServiceName: CryptoServiceName,
		EventType:   "HSM_OPERATION",
		Operation:   opCtx.operation,
		Success:     *err == nil,
		ErrMsg:      helpers.ErrToString(*err),
		StatusCode:  exceptions.GetCode(*err),
		ActorType:   "SERVICE",
		DurationMs:  time.Since(opCtx.start).Milliseconds(),
		Metadata: map[string]interface{}{
			"label": opCtx.keyLabel,
		},
	}
	if s.auditDispatcher != nil {
		s.auditDispatcher.AuditOperation(ctx, data, nil)
	}
}

// Método auxiliar para obtener clave HSM por label y tenant
func (s *cryptoService) getHSMKeyByLabel(ctx context.Context, label, tenantID string) (*entities.HSMKey, error) {
	slot, err := s.getSlotForTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// List all keys and filter by tenant and label
	allKeys, err := s.hsmManager.ListKeys(ctx, int(slot.SlotNumber))
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

func (s *cryptoService) SignData(
	ctx context.Context,
	keyLabel string,
	data []byte,
	tenantID string,
	identityContext *valueobjects.IdentityContext,
) (signature []byte, err error) {
	opCtx := &cryptoOperationContext{
		keyLabel:  keyLabel,
		tenantID:  tenantID,
		operation: "SIGN_DATA",
		start:     time.Now(),
	}
	defer s.auditCryptoOperation(ctx, &err, opCtx)

	// Get HSM key and validate usage
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return nil, err
	}

	if err := s.validateKeyUsageForOperation(hsmKey, valueobjects.KeyUsageSigning); err != nil {
		return nil, err
	}

	// Hash data
	hash := sha256.Sum256(data)

	// Get slot
	slot, err := s.getSlotForTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Sign hash using HSM
	signature, err = s.hsmManager.SignHash(
		ctx,
		hsmKey.KeyHandle,
		hash[:],
		int(slot.SlotNumber),
		identityContext,
	)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=sign_data")
	}

	return signature, nil
}

func (s *cryptoService) VerifySignature(ctx context.Context, keyLabel string, data, signature []byte, tenantID string) (valid bool, err error) {
	opCtx := &cryptoOperationContext{
		keyLabel:  keyLabel,
		tenantID:  tenantID,
		operation: "VERIFY_SIGNATURE",
		start:     time.Now(),
	}
	defer s.auditCryptoOperation(ctx, &err, opCtx)

	// Get HSM key and validate usage
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return false, err
	}

	if err := s.validateKeyUsageForOperation(hsmKey, valueobjects.KeyUsageSigning); err != nil {
		return false, err
	}

	// Hash data
	hash := sha256.Sum256(data)

	// Get slot
	slot, err := s.getSlotForTenant(ctx, tenantID)
	if err != nil {
		return false, err
	}

	// Verify signature using HSM
	valid, err = s.hsmManager.VerifySignature(ctx, hsmKey.KeyHandle, hash[:], signature, int(slot.SlotNumber))
	if err != nil {
		return false, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=verify_signature")
	}

	return valid, nil
}

func (s *cryptoService) EncryptData(ctx context.Context, keyLabel string, plaintext []byte, tenantID string) (ciphertext []byte, err error) {
	opCtx := &cryptoOperationContext{
		keyLabel:  keyLabel,
		tenantID:  tenantID,
		operation: "ENCRYPT_DATA",
		start:     time.Now(),
	}
	defer s.auditCryptoOperation(ctx, &err, opCtx)

	// Get HSM key and validate usage
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return nil, err
	}

	if err := s.validateKeyUsageForOperation(hsmKey, valueobjects.KeyUsageEncryption); err != nil {
		return nil, err
	}

	// Get slot
	slot, err := s.getSlotForTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Encrypt data using HSM
	ciphertext, err = s.hsmManager.Encrypt(ctx, hsmKey.KeyHandle, plaintext, int(slot.SlotNumber))
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=encrypt")
	}

	return ciphertext, nil
}

func (s *cryptoService) DecryptData(ctx context.Context, keyLabel string, ciphertext []byte, tenantID string) (plaintext []byte, err error) {
	opCtx := &cryptoOperationContext{
		keyLabel:  keyLabel,
		tenantID:  tenantID,
		operation: "DECRYPT_DATA",
		start:     time.Now(),
	}
	defer s.auditCryptoOperation(ctx, &err, opCtx)

	// Get HSM key and validate usage
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return nil, err
	}

	if err := s.validateKeyUsageForOperation(hsmKey, valueobjects.KeyUsageEncryption); err != nil {
		return nil, err
	}

	// Get slot
	slot, err := s.getSlotForTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Decrypt data using HSM
	plaintext, err = s.hsmManager.Decrypt(ctx, hsmKey.KeyHandle, ciphertext, int(slot.SlotNumber))
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=decrypt")
	}

	return plaintext, nil
}

func (s *cryptoService) SignHash(
	ctx context.Context,
	keyLabel string,
	hash []byte,
	tenantID string,
	identityContext *valueobjects.IdentityContext,
) (signature []byte, err error) {
	opCtx := &cryptoOperationContext{
		keyLabel:  keyLabel,
		tenantID:  tenantID,
		operation: "SIGN_HASH",
		start:     time.Now(),
	}
	defer s.auditCryptoOperation(ctx, &err, opCtx)

	// Get HSM key and validate usage
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return nil, err
	}

	if err := s.validateKeyUsageForOperation(hsmKey, valueobjects.KeyUsageSigning); err != nil {
		return nil, err
	}

	// Get slot
	slot, err := s.getSlotForTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Sign hash directly using HSM
	signature, err = s.hsmManager.SignHash(
		ctx,
		hsmKey.KeyHandle,
		hash,
		int(slot.SlotNumber),
		identityContext,
	)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=sign_hash")
	}

	return signature, nil
}

func (s *cryptoService) VerifyHashSignature(ctx context.Context, keyLabel string, hash, signature []byte, tenantID string) (valid bool, err error) {
	opCtx := &cryptoOperationContext{
		keyLabel:  keyLabel,
		tenantID:  tenantID,
		operation: "VERIFY_HASH_SIGNATURE",
		start:     time.Now(),
	}
	defer s.auditCryptoOperation(ctx, &err, opCtx)

	// Get HSM key and validate usage
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return false, err
	}

	if err := s.validateKeyUsageForOperation(hsmKey, valueobjects.KeyUsageSigning); err != nil {
		return false, err
	}

	// Get slot
	slot, err := s.getSlotForTenant(ctx, tenantID)
	if err != nil {
		return false, err
	}

	// Verify hash signature using HSM
	valid, err = s.hsmManager.VerifySignature(ctx, hsmKey.KeyHandle, hash, signature, int(slot.SlotNumber))
	if err != nil {
		return false, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=verify_hash_signature")
	}
	return valid, nil
}
