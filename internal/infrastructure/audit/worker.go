package audit

import (
	"context"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"hsm-service/pkg/request"
	"log"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	auditBufferSize  = 1000
	auditWorkerCount = 3
	auditTimeout     = 5 * time.Second
)

type WorkerConfig struct {
	WorkerCount  int
	BufferSize   int
	FlushTimeout time.Duration
}

type AuditWorker struct {
	auditClient   input.AuditRecorder // Interface, no implementación concreta
	EventsChannel chan entities.AuditEvent
	workerGroup   *errgroup.Group
	WorkerCtx     context.Context
	workerCancel  context.CancelFunc
	mutex         sync.RWMutex
}

var _ output.AuditEventDispatcher = (*AuditWorker)(nil)

func NewAuditWorker(auditClient input.AuditRecorder) output.AuditEventDispatcher {
	// Create worker context and group
	workerCtx, workerCancel := context.WithCancel(context.Background())
	workerGroup, _ := errgroup.WithContext(workerCtx)

	client := &AuditWorker{
		auditClient:   auditClient,
		EventsChannel: make(chan entities.AuditEvent, auditBufferSize),
		workerGroup:   workerGroup,
		WorkerCtx:     workerCtx,
		workerCancel:  workerCancel,
	}

	// Only start audit workers if audit client is provided
	if auditClient != nil {
		client.startAuditWorkers()
	}

	log.Printf("INFO: AuditWorker initialized successfully with %d workers", auditWorkerCount)
	return client
}

// startAuditWorkers starts multiple workers to handle audit events
func (w *AuditWorker) startAuditWorkers() {
	for range auditWorkerCount {
		w.workerGroup.Go(func() error {
			return w.auditWorker()
		})
	}
}

// auditWorker processes audit events from the channel
func (w *AuditWorker) auditWorker() error {
	for {
		select {
		case <-w.WorkerCtx.Done():
			return w.WorkerCtx.Err()
		case event, ok := <-w.EventsChannel:
			if !ok {
				// Channel closed, worker should exit
				return nil
			}
			if err := w.recordAuditEvent(&event); err != nil {
				log.Printf("WARNING: Failed to record audit event: %v", err)
				// Optionally implement retry logic here
			}
		}
	}
}

// recordAuditEvent records a single audit event with timeout
func (w *AuditWorker) recordAuditEvent(event *entities.AuditEvent) error {
	if w.auditClient == nil {
		return nil // No audit client configured, skip silently
	}

	ctx, cancel := context.WithTimeout(w.WorkerCtx, auditTimeout)
	defer cancel()

	return w.auditClient.RecordEvent(ctx, event)
}

// SendEvent enqueues an event for asynchronous processing
// This is a non-blocking operation with a timeout
func (w *AuditWorker) SendEvent(event entities.AuditEvent) {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	if w.auditClient == nil {
		return // No audit client configured, skip silently
	}

	// Non-blocking send with timeout
	select {
	case w.EventsChannel <- event:
		// log.Printf("INFO: Audit event queued: %s", event.EventAction)
		// Event queued successfully
	case <-time.After(100 * time.Millisecond):
		log.Printf("WARNING: Audit event queue full, dropping event: %s", event.EventAction)
	case <-w.WorkerCtx.Done():
		// Worker is closing
		log.Println("WARNING: Audit Event Closing")
	}
}

// Close gracefully shuts down the audit worker
func (w *AuditWorker) Close() error {
	if w.auditClient == nil {
		return nil // Nothing to close
	}

	log.Printf("INFO: Shutting down AuditWorker...")

	// Signal workers to stop
	w.workerCancel()

	// Close channel to signal no more events
	close(w.EventsChannel)

	// Wait for all workers to finish processing
	if err := w.workerGroup.Wait(); err != nil && err != context.Canceled {
		log.Printf("WARNING: Error waiting for audit workers: %v", err)
		return err
	}

	log.Printf("INFO: AuditWorker shut down successfully")
	return nil
}

// auditOperation logs an HSM operation
func (w *AuditWorker) AuditOperation(
	ctx context.Context,
	data valueobjects.AuditData,
) {
	w.mutex.RLock()
	worker := w.auditClient
	w.mutex.RUnlock()

	if worker == nil {
		return
	}

	cxtMetadata := request.ContextValuesFromContext(ctx)

	// extracting data from map[string]

	event := entities.AuditEvent{
		Timestamp:     time.Now().UTC(),
		CorrelationID: cxtMetadata.CorrelationID,
		SessionID:     cxtMetadata.SessionID,
		RequestID:     cxtMetadata.RequestID,
		ServiceName:   data.ServiceName,
		EventType:     data.EventType,
		EventAction:   data.Operation,
		TenantID:      cxtMetadata.TenantID,
		ResourceID:    data.ResourceID,
		ResourceType:  data.ResourceType,
		ActorType:     entities.ActorType(data.ActorType),
		ActorID:       cxtMetadata.Actor,
		Success:       data.Success,
		StatusCode:    data.StatusCode,
		ErrorMessage:  data.ErrMsg,
		IPAddress:     cxtMetadata.IPAddress,
		UserAgent:     cxtMetadata.UserAgent,
		DurationMs:    data.DurationMs,
		Metadata:      data.Metadata,
	}

	// Delegate to worker (non-blocking with internal timeout)
	w.SendEvent(event)
}
