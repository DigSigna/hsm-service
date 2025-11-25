package audit

import (
	"context"
	"encoding/json"
	"log"
	"platform-templates/templates/template-go-gin/internal/domain/entities"
	"platform-templates/templates/template-go-gin/internal/domain/ports/output"
)

type MockAuditClient struct{}

func NewMockAuditClient() output.AuditClient {
	return &MockAuditClient{}
}

func (m *MockAuditClient) LogSecurityEvent(ctx context.Context, event entities.AuditEvent) error {
	eventJSON, _ := json.Marshal(event)
	log.Printf("[AUDIT MOCK] Security Event: %s", string(eventJSON))
	return nil
}

func (m *MockAuditClient) LogBusinessEvent(ctx context.Context, event entities.AuditEvent) error {
	eventJSON, _ := json.Marshal(event)
	log.Printf("[AUDIT MOCK] Business Event: %s", string(eventJSON))
	return nil
}

func (m *MockAuditClient) LogSystemEvent(ctx context.Context, event entities.AuditEvent) error {
	eventJSON, _ := json.Marshal(event)
	log.Printf("[AUDIT MOCK] System Event: %s", string(eventJSON))
	return nil
}

func (m *MockAuditClient) Close() error {
	return nil
}
