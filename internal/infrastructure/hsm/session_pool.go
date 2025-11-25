package hsm

import (
	"context"
	"fmt"
	"sync"
	"time"

	"hsm-service/internal/infrastructure/config"

	"github.com/miekg/pkcs11"
	"golang.org/x/sync/semaphore"
)

type SessionPool struct {
	ctx         *pkcs11.Ctx
	slotID      uint
	pin         string
	sessions    chan pkcs11.SessionHandle
	sem         *semaphore.Weighted
	maxSessions int
	mutex       sync.Mutex
	initialized bool
}

func NewSessionPool(cfg *config.HSMConfig) (*SessionPool, error) {
	ctx := pkcs11.New(cfg.LibraryPath)
	if ctx == nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library from %s", cfg.LibraryPath)
	}

	err := ctx.Initialize()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return nil, fmt.Errorf("no slots found")
	}

	// Buscar el token por label
	var slotID uint
	found := false
	for _, slot := range slots {
		tokenInfo, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if tokenInfo.Label == cfg.TokenLabel {
			slotID = slot
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("token with label %s not found", cfg.TokenLabel)
	}

	pool := &SessionPool{
		ctx:         ctx,
		slotID:      slotID,
		pin:         cfg.Pin,
		sessions:    make(chan pkcs11.SessionHandle, cfg.MaxSessions),
		sem:         semaphore.NewWeighted(int64(cfg.MaxSessions)),
		maxSessions: cfg.MaxSessions,
	}

	// Pre-calentar el pool con algunas sesiones
	for i := 0; i < min(2, cfg.MaxSessions); i++ {
		session, err := pool.createSession()
		if err == nil {
			pool.sessions <- session
		}
	}

	pool.initialized = true
	return pool, nil
}

func (p *SessionPool) GetSession(ctx context.Context) (pkcs11.SessionHandle, error) {
	if !p.initialized {
		return 0, fmt.Errorf("session pool not initialized")
	}

	// Esperar por un permiso con timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := p.sem.Acquire(timeoutCtx, 1); err != nil {
		return 0, fmt.Errorf("failed to acquire semaphore: %w", err)
	}

	select {
	case session := <-p.sessions:
		return session, nil
	case <-ctx.Done():
		p.sem.Release(1)
		return 0, ctx.Err()
	default:
		// Crear nueva sesión si no hay disponibles
		return p.createSession()
	}
}

func (p *SessionPool) ReturnSession(session pkcs11.SessionHandle) {
	if !p.initialized {
		return
	}

	select {
	case p.sessions <- session:
		// Sesión devuelta al pool exitosamente
	default:
		// Pool lleno, cerrar sesión
		p.ctx.CloseSession(session)
	}
	p.sem.Release(1)
}

func (p *SessionPool) createSession() (pkcs11.SessionHandle, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	session, err := p.ctx.OpenSession(p.slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return 0, fmt.Errorf("failed to open session: %w", err)
	}

	err = p.ctx.Login(session, pkcs11.CKU_USER, p.pin)
	if err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		p.ctx.CloseSession(session)
		return 0, fmt.Errorf("failed to login: %w", err)
	}

	return session, nil
}

func (p *SessionPool) Close() {
	if !p.initialized {
		return
	}

	close(p.sessions)
	for session := range p.sessions {
		p.ctx.Logout(session)
		p.ctx.CloseSession(session)
	}

	if p.ctx != nil {
		p.ctx.Finalize()
		p.ctx.Destroy()
	}

	p.initialized = false
}

// HealthCheck verifica que el pool esté funcionando
func (p *SessionPool) HealthCheck() error {
	if !p.initialized {
		return fmt.Errorf("session pool not initialized")
	}

	session, err := p.GetSession(context.Background())
	if err != nil {
		return fmt.Errorf("failed to get session for health check: %w", err)
	}
	defer p.ReturnSession(session)

	// Verificar que la sesión esté activa
	_, err = p.ctx.GetSessionInfo(session)
	if err != nil {
		return fmt.Errorf("session is not active: %w", err)
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
