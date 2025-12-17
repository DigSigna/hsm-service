package audit

import (
	"context"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"log"
	"sync"
	"time"
)

// HybridRecorder implementa estrategia híbrida (HTTP + DB fallback)
type HybridProcessor struct {
	strategy     valueobjects.AuditStrategy
	primary      output.AuditTransporter // HTTP
	fallback     output.AuditStorage     // MySQL
	circuitOpen  bool                    // Circuit breaker
	circuitMutex sync.RWMutex
	failures     int
	maxFailures  int
	resetAfter   time.Duration
	lastFailure  time.Time
	buffer       []*entities.AuditEvent
	bufferMutex  sync.Mutex
	bufferSize   int
}

var _ input.AuditRecorder = (*HybridProcessor)(nil)

func NewHybridProcessor(
	strategy valueobjects.AuditStrategy,
	primary output.AuditTransporter,
	fallback output.AuditStorage,
) *HybridProcessor {
	return &HybridProcessor{
		strategy:     strategy,
		primary:      primary,
		fallback:     fallback,
		circuitOpen:  false,
		circuitMutex: sync.RWMutex{},
		failures:     0,
		maxFailures:  5,                // 5 fallos antes de abrir circuito
		resetAfter:   30 * time.Second, // 30 segundos para resetear
		lastFailure:  time.Time{},
		buffer:       make([]*entities.AuditEvent, 0),
		bufferMutex:  sync.Mutex{},
		bufferSize:   100, // Buffer de 100 eventos
	}
}

// RecordEvent implementa input.AuditRecorder
func (p *HybridProcessor) RecordEvent(ctx context.Context, event *entities.AuditEvent) error {
	switch p.strategy {
	case valueobjects.StrategyDatabase:
		return p.fallback.Store(ctx, event)

	case valueobjects.StrategyHTTP:
		if p.primary == nil {
			return p.fallback.Store(ctx, event)
		}
		return p.primary.Send(ctx, event)

	case valueobjects.StrategyHybrid:
		if p.primary == nil {
			return p.fallback.Store(ctx, event)
		}

		// Intentar HTTP primero
		if err := p.primary.Send(ctx, event); err != nil {
			log.Printf("HTTP failed, falling back to DB: %v", err)
			return p.fallback.Store(ctx, event)
		}
		return nil

	default:
		return p.fallback.Store(ctx, event)
	}
}
