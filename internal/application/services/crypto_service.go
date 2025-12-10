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
	hsmClient  output.HSMClient
	keyRepo    output.KeyRepository
	tenantRepo output.TenantRepository
	// auditClient output.AuditClient
	auditRecorder input.AuditRecorder
}

var _ input.CryptoService = (*cryptoService)(nil)

func NewCryptoService(
	hsmClient output.HSMClient,
	keyRepo output.KeyRepository,
	tenantRepo output.TenantRepository,
	auditRecorder input.AuditRecorder,
) input.CryptoService {
	return &cryptoService{
		hsmClient:     hsmClient,
		keyRepo:       keyRepo,
		tenantRepo:    tenantRepo,
		auditRecorder: auditRecorder,
	}
}

// Método auxiliar para obtener clave HSM por label y tenant
func (s *cryptoService) getHSMKeyByLabel(ctx context.Context, label, tenantID string) (*entities.HSMKey, error) {
	// Validar tenant primero
	_, err := s.tenantRepo.FindByID(ctx, tenantID)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrTenantNotFound))
	}

	// Listar todas las claves y filtrar por tenant y label
	allKeys, err := s.hsmClient.ListKeys(ctx)
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

func (s *cryptoService) SignData(ctx context.Context, keyLabel string, data []byte, tenantID string) ([]byte, error) {
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

	// Firmar el hash usando HSM
	signature, err := s.hsmClient.SignHash(ctx, hsmKey.KeyHandle, hash[:])
	if err != nil {
		s.auditCryptoOperation(ctx, "SIGN_DATA", tenantID, keyLabel, false)
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=sign_data")
	}

	// Auditoría exitosa
	s.auditCryptoOperation(ctx, "SIGN_DATA", tenantID, keyLabel, true)

	return signature, nil
}

func (s *cryptoService) VerifySignature(ctx context.Context, keyLabel string, data, signature []byte, tenantID string) (bool, error) {
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

	// Verificar firma usando HSM
	valid, err := s.hsmClient.VerifySignature(ctx, hsmKey.KeyHandle, hash[:], signature)
	if err != nil {
		s.auditCryptoOperation(ctx, "VERIFY_SIGNATURE", tenantID, keyLabel, false)
		return false, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=verify_signature")
	}

	// Auditoría exitosa
	s.auditCryptoOperation(ctx, "VERIFY_SIGNATURE", tenantID, keyLabel, true)

	return valid, nil
}

func (s *cryptoService) EncryptData(ctx context.Context, keyLabel string, plaintext []byte, tenantID string) ([]byte, error) {
	// Obtener la clave HSM
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return nil, err
	}

	// Validar que la clave puede encriptar
	if hsmKey.Usage != valueobjects.KeyUsageEncryption && hsmKey.Usage != valueobjects.KeyUsageBoth {
		return nil, errors.New(string(exceptions.ErrInvalidKeyUsage))
	}

	// Encriptar datos usando HSM
	ciphertext, err := s.hsmClient.Encrypt(ctx, hsmKey.KeyHandle, plaintext)
	if err != nil {
		s.auditCryptoOperation(ctx, "ENCRYPT_DATA", tenantID, keyLabel, false)
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=encrypt")
	}

	// Auditoría exitosa
	s.auditCryptoOperation(ctx, "ENCRYPT_DATA", tenantID, keyLabel, true)

	return ciphertext, nil
}

func (s *cryptoService) DecryptData(ctx context.Context, keyLabel string, ciphertext []byte, tenantID string) ([]byte, error) {
	// Obtener la clave HSM
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return nil, err
	}

	// Validar que la clave puede desencriptar
	if hsmKey.Usage != valueobjects.KeyUsageEncryption && hsmKey.Usage != valueobjects.KeyUsageBoth {
		return nil, errors.New(string(exceptions.ErrInvalidKeyUsage))
	}

	// Desencriptar datos usando HSM
	plaintext, err := s.hsmClient.Decrypt(ctx, hsmKey.KeyHandle, ciphertext)
	if err != nil {
		s.auditCryptoOperation(ctx, "DECRYPT_DATA", tenantID, keyLabel, false)
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=decrypt")
	}

	// Auditoría exitosa
	s.auditCryptoOperation(ctx, "DECRYPT_DATA", tenantID, keyLabel, true)

	return plaintext, nil
}

func (s *cryptoService) SignHash(ctx context.Context, keyLabel string, hash []byte, tenantID string) ([]byte, error) {
	// Obtener la clave HSM
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return nil, err
	}

	// Validar que la clave puede firmar
	if hsmKey.Usage != valueobjects.KeyUsageSigning && hsmKey.Usage != valueobjects.KeyUsageBoth {
		return nil, errors.New(string(exceptions.ErrInvalidKeyUsage))
	}

	// Firmar el hash directamente usando HSM
	signature, err := s.hsmClient.SignHash(ctx, hsmKey.KeyHandle, hash)
	if err != nil {
		s.auditCryptoOperation(ctx, "SIGN_HASH", tenantID, keyLabel, false)
		return nil, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=sign_hash")
	}

	// Auditoría exitosa
	s.auditCryptoOperation(ctx, "SIGN_HASH", tenantID, keyLabel, true)

	return signature, nil
}

func (s *cryptoService) VerifyHashSignature(ctx context.Context, keyLabel string, hash, signature []byte, tenantID string) (bool, error) {
	// Obtener la clave HSM
	hsmKey, err := s.getHSMKeyByLabel(ctx, keyLabel, tenantID)
	if err != nil {
		return false, err
	}

	// Validar que la clave puede verificar
	if hsmKey.Usage != valueobjects.KeyUsageSigning && hsmKey.Usage != valueobjects.KeyUsageBoth {
		return false, errors.New(string(exceptions.ErrInvalidKeyUsage))
	}

	// Verificar firma del hash usando HSM
	valid, err := s.hsmClient.VerifySignature(ctx, hsmKey.KeyHandle, hash, signature)
	if err != nil {
		s.auditCryptoOperation(ctx, "VERIFY_HASH_SIGNATURE", tenantID, keyLabel, false)
		return false, errors.New(string(exceptions.ErrHSMOperationFailed) + ": operation=verify_hash_signature")
	}

	// Auditoría exitosa
	s.auditCryptoOperation(ctx, "VERIFY_HASH_SIGNATURE", tenantID, keyLabel, true)

	return valid, nil
}

// Método auxiliar para auditoría de operaciones criptográficas
func (s *cryptoService) auditCryptoOperation(ctx context.Context, action, tenantID, keyLabel string, success bool) {
	event := entities.AuditEvent{
		Action:       action,
		Actor:        "system",
		TenantID:     tenantID,
		ResourceID:   keyLabel,
		ResourceType: "HSM_KEY",
		Timestamp:    time.Now().UTC(),
		Metadata:     map[string]interface{}{"key_label": keyLabel, "success": success},
	}

	go func() {
		timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.auditRecorder.RecordEvent(timeoutCtx, &event); err != nil {
			// Log local del error de auditoría
			// log.Printf("WARNING: Failed to audit crypto operation: %v", err)
		}
	}()
}
