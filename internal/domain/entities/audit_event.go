package entities

import (
	"encoding/json"
	"time"
)

type ActorType string

const (
	ActorTypeUser     ActorType = "USER"
	ActorTypeService  ActorType = "SERVICE"
	ActorTypeSystem   ActorType = "SYSTEM"
	ActorTypeExternal ActorType = "EXTERNAL"
)

type AuditEvent struct {
	ID            string `json:"id" db:"id"`
	CorrelationID string `json:"correlation_id,omitempty" db:"correlation_id"`
	SessionID     string `json:"session_id,omitempty" db:"session_id"`
	RequestID     string `json:"request_id,omitempty" db:"request_id"`

	ServiceName string `json:"service_name" db:"service_name"`
	EventType   string `json:"event_type" db:"event_type"`
	EventAction string `json:"event_action" db:"event_action"`

	TenantID     string `json:"tenant_id,omitempty" db:"tenant_id"`
	ResourceID   string `json:"resource_id,omitempty" db:"resource_id"`
	ResourceType string `json:"resource_type,omitempty" db:"resource_type"`

	ActorType ActorType `json:"actor_type" db:"actor_type"`
	ActorID   string    `json:"actor_id" db:"actor_id"`

	Success      bool   `json:"success" db:"success"`
	StatusCode   string `json:"status_code,omitempty" db:"status_code"`
	ErrorMessage string `json:"error_message,omitempty" db:"error_message"`

	DurationMs int64  `json:"duration_ms,omitempty" db:"duration_ms"`
	IPAddress  string `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent  string `json:"user_agent,omitempty" db:"user_agent"`

	Metadata  map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	Timestamp time.Time              `json:"timestamp" db:"created_at"`
}

// ToJSON convierte el evento a JSON para HTTP
func (e *AuditEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// SetError establece el evento como fallido
func (e *AuditEvent) SetError(err error) {
	e.Success = false
	if err != nil {
		e.ErrorMessage = err.Error()
	}
}

// SetDuration calcula la duración
func (e *AuditEvent) SetDuration(start time.Time) {
	e.DurationMs = time.Since(start).Milliseconds()
}
