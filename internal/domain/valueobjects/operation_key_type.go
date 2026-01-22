package valueobjects

type OperationKeyType string

const (
	// Lifecycle operations
	OperationKeyTypeGenerate OperationKeyType = "GENERATE"
	OperationKeyTypeRotate   OperationKeyType = "ROTATE"
	OperationKeyTypeDelete   OperationKeyType = "DELETE"
	OperationKeyTypeImport   OperationKeyType = "IMPORT"
	OperationKeyTypeExport   OperationKeyType = "EXPORT"
	// Cryptographic operations
	OperationKeyTypeSigning    OperationKeyType = "SIGNING"
	OperationKeyTypeVerify     OperationKeyType = "VERIFY"
	OperationKeyTypeEncryption OperationKeyType = "ENCRYP"
	OperationKeyTypeDecryption OperationKeyType = "DECRYP"
)
