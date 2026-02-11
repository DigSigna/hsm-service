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
)

type signingService struct {
	keyRepo          output.KeyRepository
	hsmManager       output.HSMManager
	auditDispatcher  output.AuditEventDispatcher
	tenantRepo       output.TenantRepository
	keyOperationRepo output.KeyOperationRepository
	slotRepo         output.SlotRepository
}

var _ input.Signer = (*signingService)(nil)

// operationContext holds information about an operation for auditing and tracking
type operationContext struct {
	keyID           string
	identityContext *valueobjects.IdentityContext
	operationType   valueobjects.OperationKeyType
	start           time.Time
	inputSize       int
	outputSize      int
}

func NewSigningService(
	keyRepo output.KeyRepository,
	hsmManager output.HSMManager,
	auditDispatcher output.AuditEventDispatcher,
	tenantRepo output.TenantRepository,
	keyOperationRepo output.KeyOperationRepository,
	slotRepo output.SlotRepository,
) input.Signer {
	return &signingService{
		keyRepo:          keyRepo,
		hsmManager:       hsmManager,
		auditDispatcher:  auditDispatcher,
		tenantRepo:       tenantRepo,
		keyOperationRepo: keyOperationRepo,
		slotRepo:         slotRepo,
	}
}

// SignHash signs a hash using the specified key
func (s *signingService) SignHash(
	ctx context.Context,
	keyID string,
	hash []byte,
	identityContext *valueobjects.IdentityContext) (signature []byte, err error) {

	opCtx := &operationContext{
		keyID:           keyID,
		identityContext: identityContext,
		operationType:   valueobjects.OperationKeyTypeSigning,
		start:           time.Now(),
		inputSize:       len(hash),
	}
	defer s.auditAndTrackOperation(ctx, &err, opCtx, "SIGN")

	// Validate key and get slot
	key, slot, err := s.validateKeyAndGetSlot(ctx, keyID, identityContext.TenantID, valueobjects.KeyUsageSigning)
	if err != nil {
		return nil, err
	}

	// Sign the hash using the HSM
	signature, err = s.hsmManager.SignHash(ctx, key.KeyLabel, hash, int(slot.SlotNumber), identityContext)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash with key %s in slot %d: %w", keyID, int(slot.SlotNumber), err)
	}

	return signature, nil
}

// GetPublicKey retrieves the public key for a given key ID
func (s *signingService) GetPublicKey(ctx context.Context, keyID, tenantID string) (publicKey []byte, err error) {
	start := time.Now()
	defer s.auditSimpleOperation(ctx, &err, start, "GET_PUBLIC_KEY", map[string]interface{}{"key_id": keyID})

	key, err := s.keyRepo.FindByID(ctx, keyID)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrKeyNotFound))
	}

	return key.PublicKey, nil
}

// VerifyHashSignature verifies a signature against a hash
func (s *signingService) VerifyHashSignature(
	ctx context.Context,
	keyID string,
	hash, signature []byte,
	identityContext *valueobjects.IdentityContext) (isValid bool, err error) {

	opCtx := &operationContext{
		keyID:           keyID,
		identityContext: identityContext,
		operationType:   valueobjects.OperationKeyTypeVerify,
		start:           time.Now(),
		inputSize:       len(hash),
		outputSize:      len(signature),
	}
	defer s.auditAndTrackVerification(ctx, &err, &isValid, opCtx)

	// Validate key and get slot
	key, slot, err := s.validateKeyAndGetSlot(ctx, keyID, identityContext.TenantID, valueobjects.KeyUsageSigning)
	if err != nil {
		return false, err
	}

	// Verify the signature using the HSM
	isValid, err = s.hsmManager.VerifySignature(ctx, key.KeyLabel, hash, signature, int(slot.SlotNumber))
	if err != nil {
		return false, fmt.Errorf("failed to verify signature with key %s in slot %d: %w", keyID, int(slot.SlotNumber), err)
	}

	return isValid, nil
}

// validateKeyAndGetSlot validates key existence, ownership, status and usage, then retrieves the associated slot
func (s *signingService) validateKeyAndGetSlot(
	ctx context.Context,
	keyID, tenantID string,
	requiredUsage valueobjects.KeyUsage) (*entities.CryptographicKey, *entities.HSMSlot, error) {

	// Validate key exists and belongs to tenant
	key, err := s.keyRepo.FindByIDAndTenant(ctx, keyID, tenantID)
	if err != nil {
		return nil, nil, exceptions.NewDomainError(
			exceptions.ErrKeyNotFound,
			"key not found",
		).WithDetail("key_id", keyID).WithDetail("tenant_id", tenantID)
	}

	// Validate key is active
	if !key.IsActive {
		return nil, nil, exceptions.NewDomainError(
			exceptions.ErrKeyInactive,
			"key is not active",
		).WithDetail("key_id", keyID)
	}

	// Validate key usage
	if key.Purpose != requiredUsage && key.Purpose != valueobjects.KeyUsageBoth {
		return nil, nil, exceptions.NewDomainError(
			exceptions.ErrInvalidKeyUsage,
			"key usage does not allow this operation",
		).WithDetail("key_id", keyID).WithDetail("usage", string(key.Purpose))
	}

	// Get tenant to determine slot
	tenant, err := getTenantWithAudit(ctx, tenantID, s.tenantRepo, s.auditDispatcher)
	if err != nil {
		return nil, nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			tenantErrorMsg,
		).WithDetail("original_error", err.Error())
	}

	// Get slot
	slot, err := getSlotWithAudit(ctx, *tenant.HSMSlotID, s.slotRepo, s.auditDispatcher)
	if err != nil {
		return nil, nil, exceptions.NewDomainError(
			exceptions.ErrSlotNotFound,
			"error checking slot existence",
		).WithDetail("original_error", err.Error())
	}

	return key, slot, nil
}

// auditSimpleOperation performs audit logging for simple operations
func (s *signingService) auditSimpleOperation(
	ctx context.Context,
	err *error,
	start time.Time,
	operation string,
	metadata map[string]interface{}) {

	data := valueobjects.AuditData{
		ServiceName: SigningServiceName,
		EventType:   "HSM_OPERATION",
		Operation:   operation,
		Success:     *err == nil,
		ErrMsg:      helpers.ErrToString(*err),
		StatusCode:  exceptions.GetCode(*err),
		DurationMs:  time.Since(start).Milliseconds(),
		ActorType:   "SERVICE",
		Metadata:    metadata,
	}
	if s.auditDispatcher != nil {
		s.auditDispatcher.AuditOperation(ctx, data, nil)
	}
}

// auditAndTrackOperation performs audit logging and key operation tracking
func (s *signingService) auditAndTrackOperation(
	ctx context.Context,
	err *error,
	opCtx *operationContext,
	operation string) {

	// Audit operation
	metadata := map[string]interface{}{
		"key_id": opCtx.keyID,
	}
	if opCtx.inputSize > 0 {
		metadata["hash_length"] = opCtx.inputSize
	}
	s.auditSimpleOperation(ctx, err, opCtx.start, operation, metadata)

	// Track key operation
	if s.keyOperationRepo != nil {
		s.trackKeyOperation(ctx, *err, opCtx)
	}
}

// auditAndTrackVerification performs audit logging and key operation tracking for verification
func (s *signingService) auditAndTrackVerification(
	ctx context.Context,
	err *error,
	isValid *bool,
	opCtx *operationContext) {

	// Audit operation
	metadata := map[string]interface{}{
		"key_id":           opCtx.keyID,
		"hash_length":      opCtx.inputSize,
		"signature_length": opCtx.outputSize,
		"is_valid":         *isValid,
	}
	s.auditSimpleOperation(ctx, err, opCtx.start, "VERIFY_HASH_SIGNATURE", metadata)

	// Track key operation
	if s.keyOperationRepo != nil {
		s.trackKeyOperation(ctx, *err, opCtx)
	}
}

// trackKeyOperation saves key operation audit trail
func (s *signingService) trackKeyOperation(
	ctx context.Context,
	err error,
	opCtx *operationContext) {

	operation := entities.KeyOperation{
		KeyID:           opCtx.keyID,
		TenantID:        opCtx.identityContext.TenantID,
		OrganizationID:  opCtx.identityContext.OrganizationID,
		OperationType:   opCtx.operationType,
		Status:          s.getOperationStatus(err),
		Level:           valueobjects.OperationKeyLevelHigh,
		InitializedBy:   opCtx.identityContext.UserID,
		InputSizeBytes:  0,
		OutputSizeBytes: 0,
		DurationMs:      time.Since(opCtx.start).Milliseconds(),
		ResultSummary:   s.getResultSummary(err),
		ErrorDetails:    s.getErrorDetails(err),
	}

	s.keyOperationRepo.Save(ctx, operation)
}

// getOperationStatus returns the operation status based on error
func (s *signingService) getOperationStatus(err error) valueobjects.OperationKeyStatus {
	if err == nil {
		return valueobjects.OperationKeyStatusSuccess
	}
	return valueobjects.OperationKeyStatusFailed
}

// getResultSummary returns a result summary based on error
func (s *signingService) getResultSummary(err error) string {
	if err != nil {
		return err.Error()
	}
	return "Success"
}

// getErrorDetails returns error details
func (s *signingService) getErrorDetails(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
