package valueobjects

type OperationKeyStatus string

const (
	OperationKeyStatusSuccess   OperationKeyStatus = "SUCCESS"
	OperationKeyStatusFailed    OperationKeyStatus = "FAILED"
	OperationKeyStatusPending   OperationKeyStatus = "PENDING"
	OperationKeyStatusCancelled OperationKeyStatus = "CANCELLED"
)
