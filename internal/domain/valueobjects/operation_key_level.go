package valueobjects

type OperationKeyLevel string

const (
	OperationKeyLevelLow    OperationKeyLevel = "LOW"    // VERIFY, ENCRYPT
	OperationKeyLevelMedium OperationKeyLevel = "MEDIUM" // SIGNING, DECRYPTION
	OperationKeyLevelHigh   OperationKeyLevel = "HIGH"   // GENERATE, ROTATE, DELETE
)
