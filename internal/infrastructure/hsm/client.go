package hsm

import (
	"context"

	// "encoding/pem"
	"errors"
	"fmt"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"log"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
)

type SoftHSMClient struct {
	ctx             *pkcs11.Ctx
	session         pkcs11.SessionHandle
	auditDispatcher output.AuditEventDispatcher
	mutex           sync.RWMutex
	closed          bool
}

// Ensure implementation of the port
var _ output.HSMClient = (*SoftHSMClient)(nil)

func NewSoftHSMClient(modulePath, pin string, slot uint, auditDispatcher output.AuditEventDispatcher) (*SoftHSMClient, error) {
	log.Printf("DEBUG: Initializing SoftHSMClient with module: %s, slot: %d", modulePath, slot)

	// Get or initialize the shared PKCS#11 context (singleton)
	// This ensures Initialize() is called only once per process
	ctx, err := GetOrInitPKCS11Context(modulePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get PKCS#11 context: %w", err)
	}

	// Verify slots are available
	slots, err := ctx.GetSlotList(false)
	if err != nil {
		return nil, fmt.Errorf("failed to get slots: %v", err)
	}

	log.Printf("DEBUG: Found %d slots", len(slots))

	if len(slots) == 0 {
		return nil, fmt.Errorf("no PKCS#11 slots available")
	}

	// Usar slot especificado o default
	// targetSlot := slot

	log.Printf("DEBUG: Slot number: %d", slot)
	log.Printf("DEBUG: Slot PIN: %s", pin)
	log.Printf("DEBUG: Using slot ID: 0x%x", slot)

	// Open session with retry logic for concurrent access
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session on slot %d: %w", slot, err)
	}

	// Get session info to check if user is already logged in
	sessionInfo, err := ctx.GetSessionInfo(session)
	if err != nil {
		ctx.CloseSession(session)
		return nil, fmt.Errorf("failed to get session info for slot %d: %w", slot, err)
	}

	// Only login if not already logged in
	// CKS_RO_USER_FUNCTIONS or CKS_RW_USER_FUNCTIONS means user is logged in
	needsLogin := sessionInfo.State != pkcs11.CKS_RO_USER_FUNCTIONS &&
		sessionInfo.State != pkcs11.CKS_RW_USER_FUNCTIONS

	if needsLogin {
		log.Printf("DEBUG: Attempting login for slot %d with PIN", slot)
		err = ctx.Login(session, pkcs11.CKU_USER, pin)
		if err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			ctx.CloseSession(session)
			return nil, fmt.Errorf("failed to login to slot %d: %w", slot, err)
		}
		log.Printf("DEBUG: Login successful for slot %d", slot)
	} else {
		log.Printf("DEBUG: User already logged in for slot %d, skipping login", slot)
	}

	client := &SoftHSMClient{
		ctx:             ctx,
		session:         session,
		auditDispatcher: auditDispatcher,
	}
	return client, nil
}

func (c *SoftHSMClient) HealthCheck(ctx context.Context) error {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if c.closed {
		return errors.New(hsmClosedMsg)
	}

	start := time.Now()
	_, err := c.ctx.GetSessionInfo(c.session)
	duration := time.Since(start)

	data := valueobjects.AuditData{
		ServiceName: "soft-hsm-client",
		EventType:   "HSM_OPERATION",
		Operation:   "HEALTH_CHECK",
		ActorType:   "EXTERNAL",
		Success:     err == nil,
		ErrMsg:      errToString(err),
		StatusCode:  exceptions.GetCode(err),
		DurationMs:  duration.Milliseconds(),
	}

	if c.auditDispatcher != nil {
		c.auditDispatcher.AuditOperation(ctx, data, nil)
	}

	return err
}

// Close closes the HSM connection gracefully
func (c *SoftHSMClient) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true

	log.Printf("INFO: Closing SoftHSMClient...")
	// Clean up PKCS#11 resources
	var errs []error

	if c.ctx != nil {
		// Logout from the session
		_ = c.ctx.Logout(c.session)

		// Close the session for this specific slot
		_ = c.ctx.CloseSession(c.session)

		// DO NOT call Finalize() or Destroy() here - the context is shared!
		// The singleton context should only be finalized during application shutdown
		// by calling FinalizePKCS11Context() from the HSMManager.CloseAll()
	}

	log.Printf("INFO: SoftHSMClient closed successfully")

	if len(errs) > 0 {
		return fmt.Errorf("errors closing HSM client: %v", errs)
	}

	return nil
}
