package hsm

import (
	"context"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"hsm-service/internal/infrastructure/config"
	"hsm-service/pkg/logger"

	"go.uber.org/zap"
)

type HSMBootstrapper struct {
	cfg             *config.Config
	auditDispatcher output.AuditEventDispatcher
	slotRepository  output.SlotRepository
	aesKeyManager   output.AESKeyManager
	aesKMRepository output.AESKeyMetadataRepository
	zapLogger       *logger.ZapLogger
}

func NewHSMBootstrapper(
	cfg *config.Config,
	auditDispatcher output.AuditEventDispatcher,
	slotRepository output.SlotRepository,
	aesKeyManager output.AESKeyManager, // Factory te da esto
	aesKMRepository output.AESKeyMetadataRepository,
	zapLogger *logger.ZapLogger,
) *HSMBootstrapper {
	return &HSMBootstrapper{
		cfg:             cfg,
		auditDispatcher: auditDispatcher,
		slotRepository:  slotRepository,
		aesKeyManager:   aesKeyManager, // Aquí usas el AESKeyManager
		aesKMRepository: aesKMRepository,
		zapLogger:       zapLogger,
	}
}

func (b *HSMBootstrapper) Bootstrap(ctx context.Context) (*HSMManager, error) {
	hsmManager := NewHSMManager(b.auditDispatcher)

	slots, err := b.slotRepository.GetAllSlots(context.Background())
	if err != nil {
		b.zapLogger.Error("Failed to get slots from slot service", zap.Error(err))
		return nil, err
	}

	println("DEBUG: Slots length:", len(slots))
	for _, slot := range slots {
		if err := b.initializeSlot(ctx, hsmManager, slot); err != nil {
			b.zapLogger.Warn("Failed to initialize slot, skipping",
				zap.Uint("slot", slot.SlotNumber),
				zap.Error(err))
			continue
		}
	}

	if hsmManager.ClientCount() == 0 {
		b.zapLogger.Error("No HSM clients were created successfully")
		return nil, fmt.Errorf("no HSM clients were created successfully")
	}

	b.zapLogger.Info("HSM bootstrapping completed",
		zap.Int("slots_initialized", hsmManager.ClientCount()))

	return hsmManager, nil
}

func (b *HSMBootstrapper) initializeSlot(ctx context.Context, hsmManager *HSMManager, slot *entities.HSMSlot) error {
	// 1. Obtener metadata de la clave AES
	aesKey, err := b.aesKMRepository.GetMetadataByID(ctx, slot.KeyMetadataID)
	if err != nil {
		return fmt.Errorf("failed to get AES key metadata: %w", err)
	}

	println("DEBUG: slot ID:", slot.ID)
	println("DEBUG: AES Key Version ID:", aesKey.VersionID)

	// 2. unwrap the key using AESKeyManager
	slotKey, err := b.aesKeyManager.UnwrapKey(ctx, aesKey.VersionID, aesKey.WrappedDataKey)
	if err != nil {
		println("DEBUG: Error unwrapping key:", err.Error())
		println("wrapped key %x", aesKey.WrappedDataKey)
		return fmt.Errorf("failed to unwrap slot key: %w", err)
	}

	println("DEBUG: Key unwrapped successfully for slot ID:", slot.ID)

	// 3. decrypt PIN using recently unwrapped slot key
	encryptedPIN := valueobjects.EncryptAESGCM{
		IV:         slot.PIN_IV,
		Ciphertext: slot.Pin_ciphertext,
		Tag:        slot.Pin_auth_tag,
		Algorithm:  "AES-256-GCM",
		KeyID:      aesKey.VersionID,
	}

	pinBytes, err := b.aesKeyManager.DecryptWithKey(slotKey, encryptedPIN)
	if err != nil {
		println("DEBUG: Error decrypting PIN:", err.Error())
		return fmt.Errorf("failed to decrypt PIN: %w", err)
	}

	pin := string(pinBytes)
	println("DEBUG: Decrypted PIN for slot", slot.Label, ":", pin)
	println("DEBUG: PIN length:", len(pin))

	// 4. Find actual slot number by label (slot numbers can change on restart)
	var actualSlotNumber uint

	if slot.IsTemporaryID {
		println(fmt.Sprintf("DEBUG: Slot %s has TEMPORARY ID %d, resolving to real ID...",
			slot.ID, slot.SlotNumber))

		// Buscar el slot real por label
		actualSlotNumber, err = b.findSlotByLabel(slot.Label)
		if err != nil {
			b.zapLogger.Warn("Failed to resolve temporary slot ID, using stored ID",
				zap.Uint("stored_slot", slot.SlotNumber),
				zap.String("label", slot.Label),
				zap.Error(err))

			// Usar el almacenado como fallback
			actualSlotNumber = slot.SlotNumber
		} else {
			// Actualizar en base de datos con ID real
			println(fmt.Sprintf("DEBUG: Updating slot %s from temporary ID %d to real ID %d",
				slot.ID, slot.SlotNumber, actualSlotNumber))

			err = b.slotRepository.UpdateSlotNumber(ctx, slot.ID, actualSlotNumber)
			if err != nil {
				b.zapLogger.Error("Failed to update slot number in DB",
					zap.String("slot_id", slot.ID),
					zap.Uint("real_slot", actualSlotNumber),
					zap.Error(err))
			}
		}
	} else {
		// Ya es un ID real
		actualSlotNumber = slot.SlotNumber
		println(fmt.Sprintf("DEBUG: Slot %s already has REAL ID %d",
			slot.ID, actualSlotNumber))
	}

	// 5. Crear cliente HSM con el slot number real
	hsmClient, err := NewSoftHSMClient(
		b.cfg.HSM.LibraryPath,
		pin,              // decrypted PIN
		actualSlotNumber, // Use actual slot number found by label
		b.auditDispatcher,
	)
	if err != nil {
		zeroBytes(slotKey)
		zeroBytes(pinBytes)
		return fmt.Errorf("failed to create HSM client: %w", err)
	}

	// 6. Registrar cliente en el manager con el slot number real
	hsmManager.RegisterClient(int(actualSlotNumber), hsmClient)

	// 7. Limpiar datos sensibles de memoria
	zeroBytes(slotKey)
	zeroBytes(pinBytes)

	b.zapLogger.Info("Slot initialized successfully",
		zap.Uint("actual_slot", actualSlotNumber),
		zap.String("slot_id", slot.ID),
		zap.String("label", slot.Label))

	return nil
}

// findSlotByLabel searches for a slot with the given label and returns its current slot number
func (b *HSMBootstrapper) findSlotByLabel(label string) (uint, error) {
	ctx, err := GetOrInitPKCS11Context(b.cfg.HSM.LibraryPath)
	if err != nil {
		return 0, fmt.Errorf("failed to get PKCS#11 context: %w", err)
	}

	slots, err := ctx.GetSlotList(true) // true = only slots with tokens present
	if err != nil {
		return 0, fmt.Errorf("failed to get slot list: %w", err)
	}

	b.zapLogger.Debug("Searching for slot by label",
		zap.String("target_label", label),
		zap.Int("total_slots", len(slots)))

	for _, slotID := range slots {
		tokenInfo, err := ctx.GetTokenInfo(slotID)
		if err != nil {
			b.zapLogger.Debug("Failed to get token info for slot",
				zap.Uint("slot_id", uint(slotID)),
				zap.Error(err))
			continue
		}

		// CRITICAL: PKCS#11 pads labels with spaces to 32 characters
		tokenLabel := trimPKCS11String(tokenInfo.Label)

		b.zapLogger.Debug("Checking slot",
			zap.Uint("slot_id", uint(slotID)),
			zap.String("token_label", tokenLabel),
			zap.String("target_label", label))

		if tokenLabel == label {
			b.zapLogger.Info("Found slot by label",
				zap.Uint("slot_id", uint(slotID)),
				zap.String("label", label))
			return uint(slotID), nil
		}
	}

	return 0, fmt.Errorf("no slot found with label '%s'", label)
}

// trimPKCS11String removes trailing spaces from PKCS#11 padded strings
func trimPKCS11String(s string) string {
	// PKCS#11 strings are padded with spaces, we need to trim them
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != ' ' {
			return s[:i+1]
		}
	}
	return ""
}

// Función helper para limpiar bytes sensibles
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
