package services

import (
	"context"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/ports/output"
	"time"

	"github.com/google/uuid"
)

type AuditService struct {
	auditRepo output.AuditRepository
}

var _ input.AuditRecorder = (*AuditService)(nil)

func NewAuditService(auditRepo output.AuditRepository) input.AuditRecorder {
	return &AuditService{
		auditRepo: auditRepo,
	}
}

func (s *AuditService) RecordEvent(ctx context.Context, event *entities.AuditEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}

	// Set system fields
	event.ID = uuid.New().String()
	event.Timestamp = time.Now().UTC()

	return s.auditRepo.Save(ctx, event)
}

func (s *AuditService) RecordSecurityEvent(ctx context.Context, action, actor, tenantID, resourceID, resourceType string) error {
	event := &entities.AuditEvent{
		Action:       action,
		Actor:        actor,
		TenantID:     tenantID,
		ResourceID:   resourceID,
		ResourceType: resourceType,
	}

	return s.RecordEvent(ctx, event)
}
