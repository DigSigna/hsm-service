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

	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module")
	}

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11: %v", err)
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		ctx.Finalize()
		return nil, fmt.Errorf("failed to get slots: %v", err)
	}

	log.Printf("DEBUG: Found %d slots", len(slots))

	if len(slots) == 0 {
		ctx.Finalize()
		return nil, fmt.Errorf("no PKCS#11 slots available")
	}

	// Usar slot especificado o default
	targetSlot := slots[0]
	if slot < uint(len(slots)) {
		targetSlot = slots[slot]
	}

	log.Printf("DEBUG: Using slot ID: 0x%x", targetSlot)

	session, err := ctx.OpenSession(targetSlot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		return nil, fmt.Errorf("failed to open session: %v", err)
	}

	// Login
	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		ctx.CloseSession(session)
		ctx.Finalize()
		return nil, fmt.Errorf("failed to login: %v", err)
	}

	log.Printf("DEBUG: Login successful or already logged in")

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
		c.auditDispatcher.AuditOperation(ctx, data)
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
		_ = c.ctx.Logout(c.session)
		_ = c.ctx.CloseSession(c.session)
		_ = c.ctx.Finalize()
		c.ctx.Destroy()
	}

	log.Printf("INFO: SoftHSMClient closed successfully")

	if len(errs) > 0 {
		return fmt.Errorf("errors closing HSM client: %v", errs)
	}

	return nil
}
