package services

import (
	"context"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"time"
)

const (
	CryptoServiceName       = "crypto-service"
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
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			ActorType:   "SERVICE",
		}
		if auditDispatcher != nil {
			auditDispatcher.AuditOperation(ctx, data)
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

func ErrToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
