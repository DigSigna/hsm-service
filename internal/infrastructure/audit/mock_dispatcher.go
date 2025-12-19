package audit

import (
	"context"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"sync"
)

// MockAuditDispatcher es un mock para tests
type MockAuditDispatcher struct {
	Events []valueobjects.AuditData
	mutex  sync.RWMutex
}

var _ output.AuditEventDispatcher = (*MockAuditDispatcher)(nil)

func NewMockAuditDispatcher() *MockAuditDispatcher {
	return &MockAuditDispatcher{
		Events: make([]valueobjects.AuditData, 0),
	}
}

func (m *MockAuditDispatcher) AuditOperation(ctx context.Context, data valueobjects.AuditData) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.Events = append(m.Events, data)
}

func (m *MockAuditDispatcher) Close() error {
	return nil
}

func (m *MockAuditDispatcher) GetEvents() []valueobjects.AuditData {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.Events
}
