package hsm

import (
	"context"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"sync"
)

type HSMManager struct {
	clients         map[int]output.HSMClient
	auditDispatcher output.AuditEventDispatcher
	mutex           sync.RWMutex
}

var _ output.HSMManager = (*HSMManager)(nil)

func NewHSMManager(auditDispatcher output.AuditEventDispatcher) *HSMManager {
	return &HSMManager{
		clients:         make(map[int]output.HSMClient),
		auditDispatcher: auditDispatcher,
	}
}

// RegisterClient registra un cliente para un slot
func (m *HSMManager) RegisterClient(slot int, client output.HSMClient) {
	m.mutex.Lock()

	defer m.mutex.Unlock()

	if existing, ok := m.clients[slot]; ok {
		// m.logger.Warn("Overwriting existing HSM client for slot", zap.Int("slot", slot))
		if err := existing.Close(); err != nil {
			// m.logger.Error("Failed to close existing HSM client", zap.Error(err))
		}
	}

	m.clients[slot] = client
	// m.logger.Info("Registered HSM client", zap.Int("slot", slot))
}

func (m *HSMManager) GetClientForSlot(slot int) (output.HSMClient, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	println("DEBUG: Getting HSM client for slot", slot)
	client, exists := m.clients[slot]
	if !exists {
		// generate HSM client for slot if not exists
		// hsmClient, err := hsm.NewSoftHSMClient(
		// 	cfg.HSM.LibraryPath,
		// 	cfg.HSM.Pin,
		// 	slot, // Slot específico
		// 	auditDispatcher,
		// )
		println("Error: No client found for slot", slot)

		return nil, fmt.Errorf("no HSM client registered for slot %d", slot)
	}

	return client, nil
}

func (m *HSMManager) GenerateKeyPair(ctx context.Context, algorithm valueobjects.KeyAlgorithm, size int, label string, slot int) (publicKey []byte, keyHandle string, err error) {
	client, err := m.GetClientForSlot(slot)
	if err != nil {
		return nil, "", err
	}

	return client.GenerateKeyPair(ctx, algorithm, size, label)
}

func (m *HSMManager) DeleteKey(ctx context.Context, keyHandle string, slot int) error {
	client, err := m.GetClientForSlot(slot)
	if err != nil {
		return err
	}

	return client.DeleteKey(ctx, keyHandle)
}

func (m *HSMManager) ListKeys(ctx context.Context, slot int) ([]*entities.HSMKey, error) {
	client, err := m.GetClientForSlot(slot)
	if err != nil {
		return nil, err
	}

	return client.ListKeys(ctx)
}

func (m *HSMManager) GetPublicKey(ctx context.Context, keyHandle string, slot int) ([]byte, error) {
	client, err := m.GetClientForSlot(slot)
	if err != nil {
		return nil, err
	}

	return client.GetPublicKey(ctx, keyHandle)
}

func (m *HSMManager) SignHash(
	ctx context.Context,
	keyHandle string,
	hash []byte,
	slot int,
	identityContext *valueobjects.IdentityContext) ([]byte, error) {
	client, err := m.GetClientForSlot(slot)
	if err != nil {
		return nil, err
	}

	return client.SignHash(ctx, keyHandle, hash, identityContext)
}

func (m *HSMManager) VerifySignature(
	ctx context.Context,
	keyHandle string,
	hash, signature []byte, slot int) (bool, error) {
	client, err := m.GetClientForSlot(slot)
	if err != nil {
		return false, err
	}

	return client.VerifySignature(ctx, keyHandle, hash, signature)
}

func (m *HSMManager) Encrypt(ctx context.Context, keyHandle string, plaintext []byte, slot int) ([]byte, error) {
	client, err := m.GetClientForSlot(slot)
	if err != nil {
		return nil, err
	}

	return client.Encrypt(ctx, keyHandle, plaintext)
}

func (m *HSMManager) Decrypt(ctx context.Context, keyHandle string, ciphertext []byte, slot int) ([]byte, error) {
	client, err := m.GetClientForSlot(slot)
	if err != nil {
		return nil, err
	}

	return client.Decrypt(ctx, keyHandle, ciphertext)
}

func (m *HSMManager) GenerateKeyPairWithLabel(
	ctx context.Context,
	algorithm valueobjects.KeyAlgorithm,
	size int,
	label,
	tenantID string,
	slot int,
) (publicKey []byte, keyHandle string, error error) {
	client, err := m.GetClientForSlot(slot)
	if err != nil {
		return nil, "", err
	}

	return client.GenerateKeyPairWithLabel(
		ctx,
		algorithm,
		size,
		label,
		tenantID,
	)
}

func (m *HSMManager) FindKeysByLabel(ctx context.Context, labelPattern string, slot int) ([]*entities.HSMKey, error) {
	client, err := m.GetClientForSlot(slot)
	if err != nil {
		return nil, err
	}

	return client.FindKeysByLabel(ctx, labelPattern)
}

func (m *HSMManager) ClientCount() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.clients)
}

// HealthCheckAll verifica estado de todos los slots
func (m *HSMManager) HealthCheckAll() map[int]bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	status := make(map[int]bool)
	for slot, client := range m.clients {
		if err := client.HealthCheck(context.Background()); err != nil {
			// m.logger.Warn("HSM client health check failed",
			// 	zap.Int("slot", slot),
			// 	zap.Error(err))
			status[slot] = false
		} else {
			status[slot] = true
		}
	}

	return status
}

// HealthCheck verifica estado de un slot específico
func (m *HSMManager) HealthCheck(ctx context.Context, slot int) error {
	client, err := m.GetClientForSlot(slot)
	if err != nil {
		return err
	}

	return client.HealthCheck(ctx)
}

// CloseAll cierra todas las conexiones
func (m *HSMManager) CloseAll() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	var lastErr error
	for _, client := range m.clients {
		if err := client.Close(); err != nil {
			// m.logger.Error("Failed to close HSM client",
			// 	zap.Int("slot", slot),
			// 	zap.Error(err))
			lastErr = err
		}
	}
	if m.auditDispatcher != nil {
		m.auditDispatcher.Close()
	}

	m.clients = make(map[int]output.HSMClient)

	// Finalize the shared PKCS#11 context after all clients are closed
	// This should be the LAST operation during application shutdown
	if err := FinalizePKCS11Context(); err != nil {
		if lastErr == nil {
			lastErr = err
		}
		// Log error but don't fail if there was already an error from clients
	}

	return lastErr
}

func (m *HSMManager) Close(slot int) error {
	client, err := m.GetClientForSlot(slot)
	if err != nil {
		return err
	}

	client.Close()

	return nil
}
