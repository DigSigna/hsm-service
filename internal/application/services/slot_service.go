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
	"hsm-service/pkg/helpers"
	"os/exec"
	"strings"
	"time"

	"github.com/miekg/pkcs11"
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

func (s *slotService) InitializeSlot(
	ctx context.Context,
	pin string,
	identityContext *valueobjects.IdentityContext,
) (slotID uint, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: "slot-service",
			EventType:   "HSM_OPERATION",
			Operation:   "INITIALIZE_SLOT",
			ActorType:   "EXTERNAL",
			Success:     err == nil,
			ErrMsg:      ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata: map[string]interface{}{
				"slot":      slotID,
				"tenant_id": identityContext.TenantID,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()

	// Validar que el tenant existe
	tenant, err := s.tenantRepo.FindByID(ctx, identityContext.TenantID)
	if err != nil || tenant == nil {
		return 0, exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			"tenant not found for slot initialization",
		)
	}

	// Obtener slot disponible (auto-asignar)
	availableSlots, err := s.GetAvailableSlots(ctx)
	if err != nil {
		return 0, fmt.Errorf("no available slots: %w", err)
	}

	realSlotID, err := s.initializeSlotInternal(availableSlots[0], identityContext.TenantID, pin)
	if err != nil {
		return 0, fmt.Errorf("failed to initialize slot %d: %w", availableSlots[0], err)
	}

	// Crear y registrar nuevo HSMClient para este slot
	hsmClient, err := hsm.NewSoftHSMClient(
		s.config.LibraryPath,
		pin,
		realSlotID,
		s.auditDispatcher,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to create HSM client for slot %d: %w", realSlotID, err)
	}

	s.hsmManager.RegisterClient(int(realSlotID), hsmClient)

	return realSlotID, nil
}

func (s *slotService) initializeSlotInternal(slot uint, tenantID, pin string) (uint, error) {
	// Cargar la biblioteca PKCS#11
	p, err := initPKCS11(s.config.LibraryPath)
	if err != nil {
		return 0, fmt.Errorf(exceptions.DomainErrPKCS11LibraryNotFound.Error()+": %w", err)
	}

	defer p.Finalize()

	// Inicializar el token usando PKCS#11
	label := helpers.GenerateTenantSlotLabel(tenantID)
	err = p.InitToken(slot, s.config.Pin, label)
	if err != nil {
		return 0, fmt.Errorf("failed to initialize token: %w", err)
	}

	// IMPORTANTE: Finalizar y re-inicializar el contexto PKCS#11
	// Después de InitToken, SoftHSM genera un nuevo slot ID
	// Debemos refrescar el contexto para ver el nuevo ID
	p.Finalize()

	p, err = initPKCS11(s.config.LibraryPath)
	if err != nil {
		return 0, fmt.Errorf("failed to reload PKCS#11 after init: %w", err)
	}
	// defer ya está arriba, pero ahora tenemos nuevo contexto
	err = p.Initialize()
	if err != nil {
		return 0, fmt.Errorf("PKCS#11 initialize failed: %w", err)
	}

	// Buscar el slot real usando el label
	realSlotID, err := s.findSlotByLabel(p, label)
	if err != nil {
		return 0, fmt.Errorf("failed to find initialized slot: %w", err)
	}

	// Ahora abrir sesión con el slot REAL
	session, err := p.OpenSession(realSlotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("failed to open session: %w", err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_SO, s.config.Pin)
	if err != nil {
		return 0, fmt.Errorf("SO login failed: %w", err)
	}

	// Establecer el PIN de usuario
	err = p.InitPIN(session, pin)
	if err != nil {
		return 0, fmt.Errorf("failed to set user PIN: %w", err)
	}

	p.Logout(session)

	return realSlotID, nil
}

func (s *slotService) GetAllSlots(ctx context.Context) ([]uint, error) {
	// Cargar la biblioteca PKCS#11
	p, err := initPKCS11(s.config.LibraryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library: %w", err)
	}

	// get slots from pkcs11
	slots, err := p.GetSlotList(true)

	return slots, nil
}

func (s *slotService) GetAvailableSlots(ctx context.Context) ([]uint, error) {
	p, err := initPKCS11(s.config.LibraryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library: %w", err)
	}

	// Obtener slots reales
	slots, err := p.GetSlotList(true) // true = solo slots con token presente
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}

	var availableSlots []uint
	for _, slotID := range slots {
		// Verificar si el token está inicializado
		tokenInfo, err := p.GetTokenInfo(slotID)
		if err != nil {
			continue
		}

		// Solo incluir slots NO inicializados
		if tokenInfo.Label == "" {
			availableSlots = append(availableSlots, uint(slotID))
		}
	}

	return availableSlots, nil
}

// FUNCTION UNUSED
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

func initPKCS11(libraryPath string) (*pkcs11.Ctx, error) {
	p := pkcs11.New(libraryPath)
	if p == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library")
	}
	return p, nil
}

func (s *slotService) findSlotByLabel(p *pkcs11.Ctx, label string) (uint, error) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		return 0, err
	}

	for _, slot := range slots {
		tokenInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			continue
		}

		tokenLabel := strings.TrimSpace(tokenInfo.Label)
		if tokenLabel == label {
			return uint(slot), nil
		}
	}

	return 0, fmt.Errorf("slot with label '%s' not found", label)
}
