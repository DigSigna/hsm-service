package services

import (
	"context"
	"fmt"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"hsm-service/internal/infrastructure/config"
	"hsm-service/internal/infrastructure/hsm"
	"os/exec"
	"time"
)

type slotService struct {
	hsmManager      *hsm.HSMManager
	tenantRepo      output.TenantRepository
	auditDispatcher output.AuditEventDispatcher
	config          *config.HSMConfig
}

func NewSlotService(
	hsmManager *hsm.HSMManager,
	tenantRepo output.TenantRepository,
	auditDispatcher output.AuditEventDispatcher,
	config *config.HSMConfig,
) input.SlotManager {
	return &slotService{
		hsmManager:      hsmManager,
		tenantRepo:      tenantRepo,
		auditDispatcher: auditDispatcher,
		config:          config,
	}
}

func (s *slotService) InitializeSlot(ctx context.Context, slot uint, tenantID, pin string) (err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: "slot-service",
			EventType:   "HSM_OPERATION",
			Operation:   "INITIALIZE_SLOT",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata: map[string]interface{}{
				"slot":      slot,
				"tenant_id": tenantID,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data)
		}
	}()

	// Validar que el tenant existe
	tenant, err := s.tenantRepo.FindByID(ctx, tenantID)
	if err != nil || tenant == nil {
		return exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			"tenant not found for slot initialization",
		)
	}

	// Validar que el slot no está ya en uso
	existingTenant, _ := s.tenantRepo.FindByHSMSlot(ctx, slot)
	if existingTenant != nil {
		return fmt.Errorf("slot %d already assigned to tenant %s", slot, existingTenant.ID)
	}

	// Ejecutar softhsm2-util para inicializar el token
	label := fmt.Sprintf("tenant-%s", tenantID)
	cmd := exec.CommandContext(ctx, "softhsm2-util",
		"--init-token",
		"--slot", fmt.Sprintf("%d", slot),
		"--label", label,
		"--pin", pin,
		"--so-pin", s.config.Pin,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to initialize HSM slot %d: %w, output: %s", slot, err, string(output))
	}

	// Crear y registrar nuevo HSMClient para este slot
	hsmClient, err := hsm.NewSoftHSMClient(
		s.config.LibraryPath,
		pin,
		slot,
		s.auditDispatcher,
	)
	if err != nil {
		return fmt.Errorf("failed to create HSM client for slot %d: %w", slot, err)
	}

	s.hsmManager.RegisterClient(int(slot), hsmClient)

	return nil
}

func (s *slotService) GetAvailableSlots(ctx context.Context) ([]uint, error) {
	// Ejecutar softhsm2-util --show-slots y parsear output
	cmd := exec.CommandContext(ctx, "softhsm2-util", "--show-slots")
	_, err := cmd.CombinedOutput()
	// output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get HSM slots: %w", err)
	}

	// TO DO: Parsear output para extraer slots disponibles
	// Formato: "Slot 0" "Slot 1" etc.

	return []uint{0, 1, 2, 3}, nil // Placeholder
}

func (s *slotService) DeleteSlot(ctx context.Context, slot uint) error {
	// Ejecutar softhsm2-util --delete-token
	cmd := exec.CommandContext(ctx, "softhsm2-util",
		"--delete-token",
		"--slot", fmt.Sprintf("%d", slot),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete HSM slot %d: %w, output: %s", slot, err, string(output))
	}

	return nil
}
