package entities

import "hsm-service/internal/domain/valueobjects"

type KeyOperation struct {
	ID              string                          `json:"id"`
	KeyID           string                          `json:"key_id"`
	TenantID        string                          `json:"tenant_id"`
	OrganizationID  *string                         `json:"organization_id,omitempty"`
	OperationType   valueobjects.OperationKeyType   `json:"operation_type,omitempty"`
	Status          valueobjects.OperationKeyStatus `json:"status"`
	Level           valueobjects.OperationKeyLevel  `json:"level,omitempty"`
	InitializedBy   string                          `json:"initialized_by,omitempty"`
	SessionID       uint                            `json:"session_id,omitempty"`
	RequestID       string                          `json:"request_id,omitempty"`
	InputSizeBytes  int                             `json:"input_size_bytes,omitempty"`
	OutputSizeBytes int                             `json:"output_size_bytes,omitempty"`
	DurationMs      int64                           `json:"duration_ms,omitempty"`
	ResultSummary   string                          `json:"result_summary,omitempty"`
	ErrorDetails    string                          `json:"error_details,omitempty"`
	CreatedAt       int64                           `json:"created_at,omitempty"`
}

func (k *KeyOperation) NewKeyOperation() *KeyOperation {
	return &KeyOperation{}
}
