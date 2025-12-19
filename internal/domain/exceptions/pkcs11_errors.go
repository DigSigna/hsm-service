package exceptions

// import "fmt"

// type ErrorCode string

// const (
// 	ErrInvalidAlgorithm   ErrorCode = "ERR_INVALID_ALGORITHM"
// 	ErrInvalidKeySize     ErrorCode = "ERR_INVALID_KEY_SIZE"
// )

// type PKCS11Error struct {
// 	Code    ErrorCode
// 	Message string
// 	Details map[string]interface{}
// }

// func (e *PKCS11Error) Error() string {
// 	return fmt.Sprintf("%s: %s", e.Code, e.Message)
// }

// func NewPKCS11Error(code ErrorCode, message string) *PKCS11Error {
// 	return &PKCS11Error{
// 		Code:    code,
// 		Message: message,
// 		Details: make(map[string]interface{}),
// 	}
// }

// func WrapError(code ErroCode, message string, err error) *PKCS11Error {
// 	pe := NewPKCS11Error(code, message)

// 	if err != nil {
// 		pe.Details["original_error"] = err.Error()
// 	}
// }

// var (
// 	ErrAlgorithmNotSupported = NewPKCS11Error(ErrInvalidAlgorithm, "The specified algorithm is not supported")
// 	ErrKeySizeTooSmall       = NewPKCS11Error(ErrInvalidKeySize, "The specified key size is too small")
// )
