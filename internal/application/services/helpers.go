package services

import (
	"context"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"hsm-service/pkg/helpers"
	"math/rand"
	"time"
)

const (
	CryptoServiceName       = "CRYPTO_SERVICE"
	tenantErrorMsg          = "error validating tenant existence"
	KeyServiceName          = "key-service"
	SigningServiceName      = "signing-service"
	TenantHelperServiceName = "tenant-helper-service"
	HSMKeyServiceName       = "hsm-key-service"
)

// getTenantWithAudit es un helper compartido para obtener tenant con auditoría
func getTenantWithAudit(
	ctx context.Context,
	tenantID string,
	tenantRepo output.TenantRepository,
	auditDispatcher output.AuditEventDispatcher,
) (tenant *entities.Tenant, err error) {
	start := time.Now()
	defer func() {

		data := valueobjects.AuditData{
			ServiceName: TenantHelperServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "GET_TENANT",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
		}
		if auditDispatcher != nil {
			auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()

	tenant, err = tenantRepo.FindByID(ctx, tenantID)

	if err != nil {

		return nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			"error checking tenant existence",
		).WithDetail("original_error", err.Error())
	}

	if tenant == nil {
		return nil, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			"tenant not found",
		).WithDetail("tenant_id", tenantID)
	}

	return tenant, nil
}

func getSlotWithAudit(
	ctx context.Context,
	slotID string,
	slotRepo output.SlotRepository,
	auditDispatcher output.AuditEventDispatcher,
) (slot *entities.HSMSlot, err error) {
	start := time.Now()
	defer func() {

		data := valueobjects.AuditData{
			ServiceName: TenantHelperServiceName,
			EventType:   "HSM_OPERATION",
			Operation:   "GET_SLOT",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
		}
		if auditDispatcher != nil {
			auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()

	slot, err = slotRepo.GetSlotByID(ctx, slotID)

	if err != nil {
		return nil, exceptions.DomainErrSlotNotFound.WithDetail("original_error", err.Error())
	}

	if slot == nil {
		return nil, exceptions.DomainErrSlotNotFound.WithDetail("slot_id", slotID)
	}

	return slot, nil
}
func genRandomPIN() string {
	pin := rand.Intn(9000) + 1000 // asegura que el PIN tenga 4 dígitos
	return fmt.Sprintf("%04d", pin)
}
