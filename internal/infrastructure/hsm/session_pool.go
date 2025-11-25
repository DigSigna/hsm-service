package hsm

import (
	"context"
	"fmt"
	"sync"

	// "time"

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
}

func NewSessionPool(ctx *pkcs11.Ctx, slotID uint, pin string, maxSessions int) *SessionPool {
	pool := &SessionPool{
		ctx:         ctx,
		slotID:      slotID,
		pin:         pin,
		sessions:    make(chan pkcs11.SessionHandle, maxSessions),
		sem:         semaphore.NewWeighted(int64(maxSessions)),
		maxSessions: maxSessions,
	}

	// Pre-calentar el pool con algunas sesiones
	for i := 0; i < 2; i++ {
		session, err := pool.createSession()
		if err == nil {
			pool.sessions <- session
		}
	}

	return pool
}

func (p *SessionPool) GetSession(ctx context.Context) (pkcs11.SessionHandle, error) {
	// Esperar por un permiso
	if err := p.sem.Acquire(ctx, 1); err != nil {
		return 0, fmt.Errorf("failed to acquire semaphore: %w", err)
	}

	select {
	case session := <-p.sessions:
		return session, nil
	default:
		// Crear nueva sesión si no hay disponibles
		return p.createSession()
	}
}

func (p *SessionPool) ReturnSession(session pkcs11.SessionHandle) {
	select {
	case p.sessions <- session:
		// Sesión devuelta al pool
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
	close(p.sessions)
	for session := range p.sessions {
		p.ctx.CloseSession(session)
	}
}
