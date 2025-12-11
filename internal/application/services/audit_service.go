package services

import (
	"context"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/input"
	// "hsm-service/internal/domain/ports/output"
)

type AuditService struct {
	// auditRepo output.AuditRepository
	auditRepo input.AuditRecorder
}

// var _ input.AuditRecorder = (*AuditService)(nil)

func NewAuditService(auditRepo input.AuditRecorder) input.AuditRecorder {
	// func NewAuditService(auditRepo output.AuditRepository) input.AuditRecorder {
	return &AuditService{
		auditRepo: auditRepo,
	}
}

func (s *AuditService) RecordEvent(ctx context.Context, event *entities.AuditEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}

	// return s.auditRepo.Save(ctx, event)
	return s.auditRepo.RecordEvent(ctx, event)
}
