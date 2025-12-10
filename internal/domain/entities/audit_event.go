package entities

import (
	"errors"
	"hsm-service/internal/domain/exceptions"
	"time"
)

type AuditEvent struct {
	ID           string                 `json:"id"`
	Action       string                 `json:"action"` // CREATE_KEY, SIGN_DOCUMENT, etc.
	Actor        string                 `json:"actor"`  // user_id or service_id
	TenantID     string                 `json:"tenant_id"`
	ResourceID   string                 `json:"resource_id"` // key_id, document_id, etc.
	ResourceType string                 `json:"resource_type"`
	Details      string                 `json:"details,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	IPAddress    string                 `json:"ip_address,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
}

func (e *AuditEvent) Validate() error {
	if e.Action == "" {
		return errors.New(string(exceptions.ErrInvalidAuditAction))
	}
	if e.Actor == "" {
		return errors.New(string(exceptions.ErrInvalidAuditActor))
	}
	if e.TenantID == "" {
		return errors.New(string(exceptions.ErrInvalidTenant))
	}
	if e.ResourceType == "" {
		return errors.New(string(exceptions.ErrInvalidResourceType))
	}
	return nil
}
