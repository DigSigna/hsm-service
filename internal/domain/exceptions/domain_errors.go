package exceptions

import "fmt"

type ErrorCode string

const (
	ErrInvalidKeyName      ErrorCode = "INVALID_KEY_NAME"
	ErrInvalidAlgorithm    ErrorCode = "INVALID_ALGORITHM"
	ErrInvalidKeySize      ErrorCode = "INVALID_KEY_SIZE"
	ErrInvalidTenant       ErrorCode = "INVALID_TENANT"
	ErrKeyNotFound         ErrorCode = "KEY_NOT_FOUND"
	ErrKeyInactive         ErrorCode = "KEY_INACTIVE"
	ErrInvalidKeyUsage     ErrorCode = "INVALID_KEY_USAGE"
	ErrHSMOperationFailed  ErrorCode = "HSM_OPERATION_FAILED"
	ErrInvalidToken        ErrorCode = "INVALID_TOKEN"
	ErrSessionExpired      ErrorCode = "SESSION_EXPIRED"
	ErrSessionNotFound     ErrorCode = "SESSION_NOT_FOUND"
	ErrInvalidAuditAction  ErrorCode = "INVALID_AUDIT_ACTION"
	ErrInvalidAuditActor   ErrorCode = "INVALID_AUDIT_ACTOR"
	ErrInvalidResourceType ErrorCode = "INVALID_RESOURCE_TYPE"
	ErrNotImplemented      ErrorCode = "NOT_IMPLEMENTED"
	ErrInvalidKeyAlgorithm ErrorCode = "INVALID_KEY_ALGORITHM"
	ErrTenantNotFound      ErrorCode = "TENANT_NOT_FOUND"
	ErrInvalidInput        ErrorCode = "INVALID_INPUT"
)

type DomainError struct {
	Code    ErrorCode
	Message string
	Details map[string]interface{}
}

func (e *DomainError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func NewDomainError(code ErrorCode, message string) *DomainError {
	return &DomainError{
		Code:    code,
		Message: message,
		Details: make(map[string]interface{}),
	}
}

func (e *DomainError) WithDetail(key string, value interface{}) *DomainError {
	e.Details[key] = value
	return e
}

// NewFromError crea un DomainError desde un error estándar
func NewFromError(code ErrorCode, err error) *DomainError {
	if err == nil {
		return NewDomainError(code, "")
	}

	return &DomainError{
		Code:    code,
		Message: err.Error(),
		Details: make(map[string]interface{}),
	}
}

// WrapError envuelve un error en un DomainError
func WrapError(code ErrorCode, message string, err error) *DomainError {
	de := NewDomainError(code, message)
	if err != nil {
		de.Details["original_error"] = err.Error()
	}
	return de
}

// Return ErrorCode
func GetCode(err error) string {
	if err == nil {
		return "SUCCESS"
	}

	switch v := err.(type) {
	case *DomainError:
		return string(v.Code)
	default:
		return "UNKNOWN_ERROR"
	}
}

// Errores predefinidos
var (
	DomainErrInvalidKeyName      = NewDomainError(ErrInvalidKeyName, "The provided key name is invalid")
	DomainErrInvalidAlgorithm    = NewDomainError(ErrInvalidAlgorithm, "The specified algorithm is not supported")
	DomainErrInvalidKeySize      = NewDomainError(ErrInvalidKeySize, "The specified key size is not supported")
	DomainErrInvalidTenant       = NewDomainError(ErrInvalidTenant, "The tenant ID is invalid or missing")
	DomainErrKeyNotFound         = NewDomainError(ErrKeyNotFound, "The requested key was not found")
	DomainErrKeyInactive         = NewDomainError(ErrKeyInactive, "The requested key is inactive")
	DomainErrInvalidKeyUsage     = NewDomainError(ErrInvalidKeyUsage, "The key usage is invalid for this operation")
	DomainErrHSMOperationFailed  = NewDomainError(ErrHSMOperationFailed, "The HSM operation failed")
	DomainErrInvalidToken        = NewDomainError(ErrInvalidToken, "The provided token is invalid")
	DomainErrSessionExpired      = NewDomainError(ErrSessionExpired, "The session has expired")
	DomainErrSessionNotFound     = NewDomainError(ErrSessionNotFound, "The session was not found")
	DomainErrInvalidAuditAction  = NewDomainError(ErrInvalidAuditAction, "The audit event action is invalid")
	DomainErrInvalidAuditActor   = NewDomainError(ErrInvalidAuditActor, "The audit event actor is invalid")
	DomainErrInvalidResourceType = NewDomainError(ErrInvalidResourceType, "The audit event resource type is invalid")
	DomainErrNotImplemented      = NewDomainError(ErrNotImplemented, "This feature is not yet implemented")
	DomainErrInvalidKeyAlgorithm = NewDomainError(ErrInvalidKeyAlgorithm, "The specified key algorithm is not supported")
	DomainErrTenantNotFound      = NewDomainError(ErrTenantNotFound, "The specified tenant not found")
	DomainErrInvalidInput        = NewDomainError(ErrInvalidInput, "The input provided is invalid")
)
