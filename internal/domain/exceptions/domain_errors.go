package exceptions

import "fmt"

type ErrorCode string

const (
	ErrInvalidKeyName          ErrorCode = "INVALID_KEY_NAME"
	ErrInvalidAlgorithm        ErrorCode = "INVALID_ALGORITHM"
	ErrInvalidKeySize          ErrorCode = "INVALID_KEY_SIZE"
	ErrInvalidTenant           ErrorCode = "INVALID_TENANT"
	ErrKeyNotFound             ErrorCode = "KEY_NOT_FOUND"
	ErrKeyInactive             ErrorCode = "KEY_INACTIVE"
	ErrInvalidKeyUsage         ErrorCode = "INVALID_KEY_USAGE"
	ErrHSMOperationFailed      ErrorCode = "HSM_OPERATION_FAILED"
	ErrInvalidToken            ErrorCode = "INVALID_TOKEN"
	ErrSessionExpired          ErrorCode = "SESSION_EXPIRED"
	ErrSessionNotFound         ErrorCode = "SESSION_NOT_FOUND"
	ErrInvalidAuditAction      ErrorCode = "INVALID_AUDIT_ACTION"
	ErrInvalidAuditActor       ErrorCode = "INVALID_AUDIT_ACTOR"
	ErrInvalidResourceType     ErrorCode = "INVALID_RESOURCE_TYPE"
	ErrNotImplemented          ErrorCode = "NOT_IMPLEMENTED"
	ErrInvalidKeyAlgorithm     ErrorCode = "INVALID_KEY_ALGORITHM"
	ErrTenantNotFound          ErrorCode = "TENANT_NOT_FOUND"
	ErrTenantRequired          ErrorCode = "TENANT_REQUIRED"
	ErrInvalidInput            ErrorCode = "INVALID_INPUT"
	ErrOwnerIdRequired         ErrorCode = "OWNER_ID_REQUIRED"
	ErrInvalidOwnerType        ErrorCode = "INVALID_OWNER_TYPE"
	ErrSlotNotFound            ErrorCode = "SLOT_NOT_FOUND"
	ErrCreateSlotFailed        ErrorCode = "CREATE_SLOT_FAILED"
	ErrCreateHSMMetadataFailed ErrorCode = "CREATE_HSM_METADATA_FAILED"

	ErrPKCS11LibraryNotFound ErrorCode = "PKCS11_LIBRARY_NOT_FOUND"
	// Crypto errors
	ErrInvalidAESKeySize      ErrorCode = "INVALID_AES_KEY_SIZE"
	ErrAESCreateCipher        ErrorCode = "AES_CREATE_CIPHER_FAILED"
	ErrAESCreateGCM           ErrorCode = "AES_CREATE_GCM_FAILED"
	ErrAESCreateNonce         ErrorCode = "AES_CREATE_NONCE_FAILED"
	ErrAESInvalidKey          ErrorCode = "AES_INVALID_KEY"
	ErrAESDecryptFailed       ErrorCode = "AES_DECRYPT_FAILED"
	ErrInvalidBase64          ErrorCode = "INVALID_BASE64_DATA"
	ErrKeyIDMismatch          ErrorCode = "KEY_ID_MISMATCH"
	ErrWrappingKeyLength      ErrorCode = "WRAPPING_KEY_INVALID_LENGTH"
	ErrWrappingKeyShort       ErrorCode = "WRAPPING_KEY_TOO_SHORT"
	ErrKeyToWrapLengthInvalid ErrorCode = "KEY_TO_WRAP_INVALID_LENGTH"
	ErrK8sSecretNotFound      ErrorCode = "K8S_SECRET_NOT_FOUND"
	ErrK8sKeyNotFound         ErrorCode = "K8S_KEY_NOT_FOUND"
	ErrFailWrapKey            ErrorCode = "FAIL_WRAP_KEY"
	ErrFailUUnwrapKey         ErrorCode = "FAIL_UNWRAP_KEY"
	ErrFailCreateAESKey       ErrorCode = "FAIL_CREATE_AES_KEY"
	ErrFailEncryptData        ErrorCode = "FAIL_ENCRYPT_DATA"
	ErrFailDecryptData        ErrorCode = "FAIL_DECRYPT_DATA"
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
		// For standard errors, return a generic error code without printing
		// The actual error message is still captured in the audit log
		return "INTERNAL_ERROR"
	}
}

// Errores predefinidos
var (
	DomainErrInvalidKeyName          = NewDomainError(ErrInvalidKeyName, "The provided key name is invalid")
	DomainErrInvalidAlgorithm        = NewDomainError(ErrInvalidAlgorithm, "The specified algorithm is not supported")
	DomainErrInvalidKeySize          = NewDomainError(ErrInvalidKeySize, "The specified key size is not supported")
	DomainErrInvalidTenant           = NewDomainError(ErrInvalidTenant, "The tenant ID is invalid or missing")
	DomainErrKeyNotFound             = NewDomainError(ErrKeyNotFound, "The requested key was not found")
	DomainErrKeyInactive             = NewDomainError(ErrKeyInactive, "The requested key is inactive")
	DomainErrInvalidKeyUsage         = NewDomainError(ErrInvalidKeyUsage, "The key usage is invalid for this operation")
	DomainErrHSMOperationFailed      = NewDomainError(ErrHSMOperationFailed, "The HSM operation failed")
	DomainErrInvalidToken            = NewDomainError(ErrInvalidToken, "The provided token is invalid")
	DomainErrSessionExpired          = NewDomainError(ErrSessionExpired, "The session has expired")
	DomainErrSessionNotFound         = NewDomainError(ErrSessionNotFound, "The session was not found")
	DomainErrInvalidAuditAction      = NewDomainError(ErrInvalidAuditAction, "The audit event action is invalid")
	DomainErrInvalidAuditActor       = NewDomainError(ErrInvalidAuditActor, "The audit event actor is invalid")
	DomainErrInvalidResourceType     = NewDomainError(ErrInvalidResourceType, "The audit event resource type is invalid")
	DomainErrNotImplemented          = NewDomainError(ErrNotImplemented, "This feature is not yet implemented")
	DomainErrInvalidKeyAlgorithm     = NewDomainError(ErrInvalidKeyAlgorithm, "The specified key algorithm is not supported")
	DomainErrTenantNotFound          = NewDomainError(ErrTenantNotFound, "The specified tenant not found")
	DomainErrInvalidInput            = NewDomainError(ErrInvalidInput, "The input provided is invalid")
	DomainErrTenantRequired          = NewDomainError(ErrTenantRequired, "The tenant required for this operation")
	DomainErrPKCS11LibraryNotFound   = NewDomainError(ErrPKCS11LibraryNotFound, "The PKCS#11 library was not found")
	DomainErrOwnerIdRequired         = NewDomainError(ErrOwnerIdRequired, "The owner ID is required")
	DomainErrInvalidOwnerType        = NewDomainError(ErrInvalidOwnerType, "The owner type is invalid")
	DomainErrSlotNotFound            = NewDomainError(ErrSlotNotFound, "The specified slot was not found")
	DomainErrCreateSlotFailed        = NewDomainError(ErrCreateSlotFailed, "Failed to create HSM slot")
	DomainErrCreateHSMMetadataFailed = NewDomainError(ErrCreateHSMMetadataFailed, "Failed to create HSM metadata")
	//
	DomainErrInvalidAESKeySize      = NewDomainError(ErrInvalidAESKeySize, "The AES key size is invalid")
	DomainErrAESCreateCipher        = NewDomainError(ErrAESCreateCipher, "Failed to create AES cipher")
	DomainErrAESCreateGCM           = NewDomainError(ErrAESCreateGCM, "Failed to create AES GCM instance")
	DomainErrAESCreateNonce         = NewDomainError(ErrAESCreateNonce, "Failed to create AES nonce")
	DomainErrAESInvalidKey          = NewDomainError(ErrAESInvalidKey, "The AES key is invalid")
	DomainErrAESDecryptFailed       = NewDomainError(ErrAESDecryptFailed, "AES decryption failed")
	DomainErrInvalidBase64          = NewDomainError(ErrInvalidBase64, "The provided data is not valid base64")
	DomainErrKeyIDMismatch          = NewDomainError(ErrKeyIDMismatch, "The key ID does not match")
	DomainErrWrappingKeyLength      = NewDomainError(ErrWrappingKeyLength, "The wrapping key length is invalid")
	DomainErrWrappingKeyShort       = NewDomainError(ErrWrappingKeyShort, "The wrapping key is too short")
	DomainErrKeyToWrapLengthInvalid = NewDomainError(ErrKeyToWrapLengthInvalid, "The key to wrap length is invalid")
	DomainErrK8sSecretNotFound      = NewDomainError(ErrK8sSecretNotFound, "The Kubernetes secret was not found")
	DomainErrK8sKeyNotFound         = NewDomainError(ErrK8sKeyNotFound, "The key was not found in Kubernetes secret")
	DomainErrFailWrapKey            = NewDomainError(ErrFailWrapKey, "Failed to wrap the key")
	DomainErrFailUUnwrapKey         = NewDomainError(ErrFailUUnwrapKey, "Failed to unwrap the key")
	DomainErrFailCreateAESKey       = NewDomainError(ErrFailCreateAESKey, "Failed to create AES key")
	DomainErrFailEncryptData        = NewDomainError(ErrFailEncryptData, "Failed to encrypt data")
	DomainErrFailDecryptData        = NewDomainError(ErrFailDecryptData, "Failed to decrypt data")
)
