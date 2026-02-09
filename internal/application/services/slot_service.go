package services

import (
	"context"
	"fmt"
	"hsm-service/internal/domain/entities"
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

	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
)

type cleanupHandler struct {
	ctx        context.Context
	slotRepo   output.SlotRepository
	metaRepo   output.AESKeyMetadataRepository
	operations []func()
}

type slotService struct {
	hsmManager      *hsm.HSMManager
	tenantRepo      output.TenantRepository
	auditDispatcher output.AuditEventDispatcher
	config          *config.HSMConfig
	slotRepo        output.SlotRepository
	aesKeyManager   output.AESKeyManager
	aesKMRepository output.AESKeyMetadataRepository
}

func NewSlotService(
	hsmManager *hsm.HSMManager,
	tenantRepo output.TenantRepository,
	auditDispatcher output.AuditEventDispatcher,
	config *config.HSMConfig,
	slotRepo output.SlotRepository,
	aesKeyManager output.AESKeyManager,
	aesKMRepository output.AESKeyMetadataRepository,
) input.SlotManager {
	return &slotService{
		hsmManager:      hsmManager,
		tenantRepo:      tenantRepo,
		auditDispatcher: auditDispatcher,
		config:          config,
		slotRepo:        slotRepo,
		aesKeyManager:   aesKeyManager,
		aesKMRepository: aesKMRepository,
	}
}

func (s *slotService) InitializeSlot(
	ctx context.Context,
	identityContext *valueobjects.IdentityContext,
) (slotID string, err error) {
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: "slot-service",
			EventType:   "HSM_OPERATION",
			Operation:   "INITIALIZE_SLOT",
			ActorType:   "EXTERNAL",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
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
		return "", exceptions.NewDomainError(
			exceptions.ErrTenantNotFound,
			"tenant not found for slot initialization",
		)
	}

	// Obtener slot disponible (auto-asignar)
	availableSlots, err := s.GetAvailableSlots(ctx)
	if err != nil {
		return "", fmt.Errorf("no available slots: %w", err)
	}

	pin := genRandomPIN()
	hsmSlot, err := s.initializeSlotInternal(availableSlots[0], identityContext.TenantID, pin)
	if err != nil {
		return "", fmt.Errorf("failed to initialize slot %d: %w", availableSlots[0], err)
	}

	// Crear y registrar nuevo HSMClient para este slot
	hsmClient, err := hsm.NewSoftHSMClient(
		s.config.LibraryPath,
		pin,
		hsmSlot.SlotNumber,
		s.auditDispatcher,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create HSM client for slot %d: %w", hsmSlot.SlotNumber, err)
	}

	s.hsmManager.RegisterClient(int(hsmSlot.SlotNumber), hsmClient)

	zeroBytes([]byte(pin))

	return hsmSlot.ID, nil
}

func (s *slotService) initializeSlotInternal(slot uint, tenantID, pin string) (*entities.HSMSlot, error) {
	// Cargar la biblioteca PKCS#11
	p, err := initPKCS11(s.config.LibraryPath)
	if err != nil {
		return nil, fmt.Errorf(exceptions.DomainErrPKCS11LibraryNotFound.Error()+": %w", err)
	}

	defer p.Finalize()

	// Inicializar el token usando PKCS#11
	label := helpers.GenerateTenantSlotLabel(tenantID)
	err = p.InitToken(slot, s.config.Pin, label)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize token: %w", err)
	}

	// IMPORTANTE: Finalizar y re-inicializar el contexto PKCS#11
	// Después de InitToken, SoftHSM genera un nuevo slot ID
	// Debemos refrescar el contexto para ver el nuevo ID
	p.Finalize()

	p, err = initPKCS11(s.config.LibraryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to reload PKCS#11 after init: %w", err)
	}
	// defer ya está arriba, pero ahora tenemos nuevo contexto
	err = p.Initialize()
	if err != nil {
		return nil, fmt.Errorf("PKCS#11 initialize failed: %w", err)
	}

	// Buscar el slot real usando el label
	realSlotID, err := s.findSlotByLabel(p, label)
	if err != nil {
		return nil, fmt.Errorf("failed to find initialized slot: %w", err)
	}

	// Ahora abrir sesión con el slot REAL
	session, err := p.OpenSession(realSlotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_SO, s.config.Pin)
	if err != nil {
		return nil, fmt.Errorf("SO login failed: %w", err)
	}

	// Establecer el PIN de usuario
	err = p.InitPIN(session, pin)
	if err != nil {
		return nil, fmt.Errorf("failed to set user PIN: %w", err)
	}

	p.Logout(session)

	// create persisted HSMSlot record with encrypted PIN
	hsmSlot, err := s.createHSMSlot(context.Background(), realSlotID, label, pin)
	if err != nil {
		return nil, err
	}

	return hsmSlot, nil
}

func (s *slotService) createHSMSlot(
	ctx context.Context,
	realSlotID uint,
	label string,
	pin string,
) (hsmSlot *entities.HSMSlot, err error) {
	cleaner := &cleanupHandler{
		ctx:      ctx,
		slotRepo: s.slotRepo,
		metaRepo: s.aesKMRepository,
	}

	defer func() {
		if err != nil {
			cleaner.cleanup()
		}
	}()

	slotKey, err := s.aesKeyManager.GenerateDataKey()
	masterKeyID := s.aesKeyManager.GetCurrentKeyID()
	if err != nil {
		return nil, exceptions.DomainErrAESCreateGCM.WithDetail("original_error", err.Error())
	}

	// Encrypt PIN with slot key
	encryptPin, err := s.aesKeyManager.EncryptWithKey(
		slotKey,
		[]byte(pin),
	)

	if err != nil {
		return nil, exceptions.DomainErrFailEncryptData.WithDetail("original_error", err.Error())
	}

	// wrappe slot key with master key
	wrappedDataKey, err := s.aesKeyManager.WrapKey(
		ctx,
		masterKeyID,
		slotKey,
	)
	if err != nil {
		return nil, exceptions.DomainErrFailWrapKey.WithDetail("original_error", err.Error())
	}

	metadataID := uuid.New().String()
	slotID := uuid.New().String()

	metadata := &entities.AESKeyMetadata{
		ID:                metadataID,
		HSMSlotID:         slotID,
		VersionID:         masterKeyID,
		Active:            true,
		Algorithm:         "AES-256-GCM",
		Source:            "LOCAL_GENERATED",
		Description:       "AES key for HSM slot PIN encryption",
		WrappedDataKey:    wrappedDataKey,
		WrappedKeyVersion: masterKeyID,
	}

	slot := &entities.HSMSlot{
		ID:             slotID,
		Label:          label,
		SlotNumber:     realSlotID,
		PIN_IV:         encryptPin.IV,
		Pin_ciphertext: encryptPin.Ciphertext,
		Pin_auth_tag:   encryptPin.Tag,
		KeyMetadataID:  metadataID,
		// empty json object
		EncryptionContext: map[string]interface{}{
			"slot": slotID,
		},
	}

	// Save slot and metadata in a transaction
	err = s.slotRepo.CreateSlot(ctx, *slot)
	if err != nil {
		println("Error creating slot record:", err.Error())
		return nil, exceptions.DomainErrCreateSlotFailed.WithDetail("original_error", err.Error())
	}
	cleaner.addSlotCleanup(slot.ID)

	err = s.aesKMRepository.CreateMetadata(ctx, *metadata)
	if err != nil {
		println("Error creating AES key metadata:", err.Error())
		// Rollback slot creation
		_ = s.slotRepo.DeleteSlot(ctx, slot.ID)
		return nil, exceptions.DomainErrCreateHSMMetadataFailed.WithDetail("original_error", err.Error())
	}
	cleaner.addMetadataCleanup(metadata.ID)

	zeroBytes([]byte(pin))
	zeroBytes(slotKey)
	zeroBytes(wrappedDataKey)
	zeroBytes(encryptPin.IV)
	zeroBytes(encryptPin.Ciphertext)
	zeroBytes(encryptPin.Tag)

	return slot, nil
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

func (s *slotService) DeleteSlot(ctx context.Context, slot uint) (err error) {
	println("DEBUG: Deleting slot", slot)
	start := time.Now()
	defer func() {
		data := valueobjects.AuditData{
			ServiceName: "slot-service",
			EventType:   "HSM_OPERATION",
			Operation:   "DELETE_SLOT",
			ActorType:   "SYSTEM",
			Success:     err == nil,
			ErrMsg:      helpers.ErrToString(err),
			StatusCode:  exceptions.GetCode(err),
			DurationMs:  time.Since(start).Milliseconds(),
			Metadata: map[string]interface{}{
				"slot": slot,
			},
		}
		if s.auditDispatcher != nil {
			s.auditDispatcher.AuditOperation(ctx, data, nil)
		}
	}()

	// test
	// delete token
	cmd := exec.Command("softhsm2-util", "--delete-token", "--slot", fmt.Sprintf("%d", slot))
	err = cmd.Run()

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

// Función helper para limpiar bytes sensibles
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (c *cleanupHandler) addSlotCleanup(slotID string) {
	c.operations = append(c.operations, func() {
		_ = c.slotRepo.DeleteSlot(c.ctx, slotID)
	})
}

func (c *cleanupHandler) addMetadataCleanup(metadataID string) {
	c.operations = append(c.operations, func() {
		_ = c.metaRepo.DeleteMetadata(c.ctx, metadataID)
	})
}

func (c *cleanupHandler) cleanup() {
	// Ejecutar en orden inverso (LIFO)
	for i := len(c.operations) - 1; i >= 0; i-- {
		c.operations[i]()
	}
}
