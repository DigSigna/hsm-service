package valueobjects

type AuditStrategy string

const (
	StrategyDatabase AuditStrategy = "database"
	StrategyHTTP     AuditStrategy = "http"
	StrategyHybrid   AuditStrategy = "hybrid"
	StrategyMock     AuditStrategy = "mock"
	StrategyAsync    AuditStrategy = "async"
)

func (s AuditStrategy) IsValid() bool {
	switch s {
	case StrategyDatabase, StrategyHTTP, StrategyHybrid, StrategyMock, StrategyAsync:
		return true
	default:
		return false
	}
}
