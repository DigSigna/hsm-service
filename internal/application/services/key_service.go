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
	"hsm-service/pkg/helpers"

	"time"

	"github.com/google/uuid"
)

type keyService struct {
	keyRepo          output.KeyRepository
	hsmManager       output.HSMManager
	auditDispatcher  output.AuditEventDispatcher
	tenantRepo       output.TenantRepository
	keyOperationRepo output.KeyOperationRepository
	slotRepo         output.SlotRepository
}

type contextKey string

const (
	tenantIDKey contextKey = "tenant_id"
)

var _ input.KeyManager = (*keyService)(nil)

// keyCreationContext holds information needed during key creation
type keyCreationContext struct {
	name            string
	algorithm       valueobjects.KeyAlgorithm
	size            int
	usage           valueobjects.KeyUsage
	identityContext *valueobjects.IdentityContext
	start           time.Time
}

func NewKeyService(
	keyRepo output.KeyRepository,
	hsmManager output.HSMManager,
	auditDispatcher output.AuditEventDispatcher,
	tenantRepo output.TenantRepository,
	keyOperationRepo output.KeyOperationRepository,
	slotRepo output.SlotRepository,
) input.KeyManager {
	return &keyService{
		keyRepo:          keyRepo,
		hsmManager:       hsmManager,
		auditDispatcher:  auditDispatcher,
		tenantRepo:       tenantRepo,
		keyOperationRepo: keyOperationRepo,
		slotRepo:         slotRepo,
	}
}

func (s *keyService) CreateKey(
	ctx context.Context,
	name string,
	algorithm valueobjects.KeyAlgorithm,
	size int,
	usage valueobjects.KeyUsage,
	identityContext *valueobjects.IdentityContext) (key *entities.CryptographicKey, err error) {

	ctx = context.WithValue(ctx, tenantIDKey, identityContext.TenantID)
	creationCtx := &keyCreationContext{
		name:            name,
		algorithm:       algorithm,
		size:            size,
		usage:           usage,
		identityContext: identityContext,
		start:           time.Now(),
	}

	var slot *entities.HSMSlot
	defer s.auditAndTrackKeyCreation(ctx, &key, &err, &slot, creationCtx)

	// Validate input parameters
	if err := s.validateKeyParameters(algorithm, usage); err != nil {
		return nil, err
	}

	// Get tenant and slot
	slot, err = s.getTenantSlot(ctx, identityContext.TenantID)
	if err != nil {
		return nil, err
	}

	// Generate key in HSM
	key, err = s.generateAndSaveKey(ctx, creationCtx, slot)
	if err != nil {
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

func (s *keyService) RotateKey(
	ctx context.Context,
	keyID string,
	identityContext *valueobjects.IdentityContext,
) (newKey *entities.CryptographicKey, err error) {
	start := time.Now()

	defer func() {
		data := valueobjects.AuditData{
			ServiceName: KeyServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "ROTATE_KEY",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			Metadata: map[string]interface{}{
				"key_id": keyID,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data, identityContext)
		}
	}()

	// Obtener clave existente
	existing, err := s.keyRepo.FindByIDAndTenant(ctx, keyID, identityContext.TenantID)
	if err != nil {
		return nil, err
	}

	// Crear nueva versión de la clave
	newKey, err = s.CreateKey(ctx, existing.Name+"-rotated", existing.Algorithm, existing.KeySize, existing.Purpose, identityContext)
	if err != nil {
		return nil, err
	}

	// validar tenant
	tenant, err := getTenantWithAudit(ctx, identityContext.TenantID, s.tenantRepo, s.auditDispatcher)

	if err != nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}

	// get slot
	slot, err := getSlotWithAudit(ctx, *tenant.HSMSlotID, s.slotRepo, s.auditDispatcher)

	if err != nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrSlotNotFound,
			err.Error(),
		).WithDetail("original_error", err.Error())
	}

	// Desactivar clave anterior
	existing.Deactivate()
	if err := s.keyRepo.Save(ctx, existing); err != nil {
		// Rollback: eliminar nueva clave
		s.hsmManager.DeleteKey(ctx, newKey.KeyHandle, int(slot.SlotNumber))
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
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
			Metadata: map[string]interface{}{
				"key_id": keyID,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data, nil)
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

	// get slot
	slot, err := getSlotWithAudit(ctx, *tenant.HSMSlotID, s.slotRepo, s.auditDispatcher)

	if err != nil {
		return exceptions.NewDomainError(
			exceptions.ErrSlotNotFound,
			err.Error(),
		).WithDetail("original_error", err.Error())
	}

	// Eliminar del HSM
	if err := s.hsmManager.DeleteKey(ctx, key.KeyHandle, int(slot.SlotNumber)); err != nil {
		return errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=delete_key")
	}

	// Eliminar metadata
	return s.keyRepo.Delete(ctx, keyID)
}

// validateKeyParameters validates input parameters for key creation
func (s *keyService) validateKeyParameters(algorithm valueobjects.KeyAlgorithm, usage valueobjects.KeyUsage) error {
	if !algorithm.IsValid() {
		return errors.New(string(exceptions.ErrInvalidKeyAlgorithm))
	}

	if !usage.IsValid() {
		return errors.New(string(exceptions.ErrInvalidKeyUsage))
	}

	return nil
}

// getTenantSlot retrieves the HSM slot for a given tenant
func (s *keyService) getTenantSlot(ctx context.Context, tenantID string) (*entities.HSMSlot, error) {
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
			"error checking slot existence",
		).WithDetail("original_error", err.Error())
	}

	return slot, nil
}

// generateAndSaveKey generates a key in HSM and saves its metadata
func (s *keyService) generateAndSaveKey(
	ctx context.Context,
	creationCtx *keyCreationContext,
	slot *entities.HSMSlot) (*entities.CryptographicKey, error) {

	keyLabel := fmt.Sprintf("%s_%s_%s",
		creationCtx.identityContext.TenantID,
		creationCtx.name,
		uuid.New().String()[:8])

	// Generate key pair in HSM
	publicKey, keyHandle, err := s.hsmManager.GenerateKeyPair(
		ctx,
		creationCtx.algorithm,
		creationCtx.size,
		keyLabel,
		int(slot.SlotNumber))
	if err != nil {
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=generate_key_pair")
	}

	// Create key entity
	key := &entities.CryptographicKey{
		ID:               uuid.New().String(),
		TenantID:         creationCtx.identityContext.TenantID,
		OwnerType:        creationCtx.identityContext.OwnerType,
		OwnerID:          creationCtx.identityContext.OwnerID,
		ParentKeyID:      creationCtx.identityContext.ParentKeyID,
		CertLevel:        creationCtx.identityContext.CertLevel,
		Name:             creationCtx.name,
		Alias:            keyLabel,
		Algorithm:        creationCtx.algorithm,
		KeySize:          creationCtx.size,
		Purpose:          creationCtx.usage,
		PublicKey:        publicKey,
		KeyHandle:        keyHandle,
		KeyLabel:         keyLabel,
		IsHardwareBacked: true,
		HSMSlotID:        slot.ID,
		Version:          1,
		ExpirationDate:   time.Now().Add(365 * 24 * time.Hour), // 1 year default
		IsActive:         true,
	}

	// Validate entity
	if err := key.Validate(); err != nil {
		// Rollback: delete key from HSM
		s.hsmManager.DeleteKey(ctx, keyHandle, int(slot.SlotNumber))
		return nil, err
	}

	// Save to repository
	if err := s.keyRepo.Save(ctx, key); err != nil {
		// Rollback: delete key from HSM
		s.hsmManager.DeleteKey(ctx, keyHandle, int(slot.SlotNumber))
		return nil, err
	}

	return key, nil
}

// auditAndTrackKeyCreation performs audit logging and key operation tracking for key creation
func (s *keyService) auditAndTrackKeyCreation(
	ctx context.Context,
	key **entities.CryptographicKey,
	err *error,
	slot **entities.HSMSlot,
	creationCtx *keyCreationContext) {

	// Build metadata
	metadata := map[string]interface{}{
		"key_name":        creationCtx.name,
		"algorithm":       creationCtx.algorithm,
		"key_size":        creationCtx.size,
		"usage":           creationCtx.usage,
		"parent_key_id":   creationCtx.identityContext.ParentKeyID,
		"organization_id": creationCtx.identityContext.OrganizationID,
	}
	if *slot != nil {
		metadata["slot_id"] = (*slot).ID
	}

	// Audit operation
	data := valueobjects.AuditData{
		ServiceName: KeyServiceName,
		EventType:   "HSM_OPERATION",
		Operation:   "CREATE_KEY",
		Success:     *err == nil,
		ErrMsg:      helpers.ErrToString(*err),
		StatusCode:  exceptions.GetCode(*err),
		DurationMs:  time.Since(creationCtx.start).Milliseconds(),
		ActorType:   "SERVICE",
		Metadata:    metadata,
	}
	if s.auditDispatcher != nil {
		s.auditDispatcher.AuditOperation(ctx, data, creationCtx.identityContext)
	}

	// Track key operation only if key was successfully created
	if *key != nil && (*key).ID != "" && s.keyOperationRepo != nil {
		operation := entities.KeyOperation{
			KeyID:           (*key).ID,
			TenantID:        creationCtx.identityContext.TenantID,
			OrganizationID:  creationCtx.identityContext.OrganizationID,
			OperationType:   valueobjects.OperationKeyTypeGenerate,
			Status:          s.getOperationStatus(*err),
			Level:           valueobjects.OperationKeyLevelHigh,
			InitializedBy:   creationCtx.identityContext.UserID,
			InputSizeBytes:  0,
			OutputSizeBytes: 0,
			DurationMs:      time.Since(creationCtx.start).Milliseconds(),
			ResultSummary:   s.getResultSummary(*err),
			ErrorDetails:    s.getErrorDetails(*err),
		}

		s.keyOperationRepo.Save(ctx, operation)
	}
}

// getOperationStatus returns the operation status based on error
func (s *keyService) getOperationStatus(err error) valueobjects.OperationKeyStatus {
	if err == nil {
		return valueobjects.OperationKeyStatusSuccess
	}
	return valueobjects.OperationKeyStatusFailed
}

// getResultSummary returns a result summary based on error
func (s *keyService) getResultSummary(err error) string {
	if err != nil {
		return err.Error()
	}
	return "Success"
}

// getErrorDetails returns error details
func (s *keyService) getErrorDetails(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
