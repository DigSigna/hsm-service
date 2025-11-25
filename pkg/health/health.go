package health

import (
	"context"
	"database/sql"
	"time"

	"github.com/redis/go-redis/v9"
)

type HealthStatus struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Checks    map[string]string `json:"checks,omitempty"`
}

type HealthChecker struct {
	db       *sql.DB
	redis    *redis.Client
	services map[string]func() error
}

func NewHealthChecker(db *sql.DB, redis *redis.Client) *HealthChecker {
	checker := &HealthChecker{
		db:       db,
		redis:    redis,
		services: make(map[string]func() error),
	}

	// Register default checks
	checker.RegisterCheck("database", checker.checkDatabase)
	checker.RegisterCheck("redis", checker.checkRedis)

	return checker
}

func (h *HealthChecker) RegisterCheck(name string, check func() error) {
	h.services[name] = check
}

func (h *HealthChecker) Check() HealthStatus {
	status := HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now().UTC(),
		Checks:    make(map[string]string),
	}

	for name, check := range h.services {
		if err := check(); err != nil {
			status.Status = "unhealthy"
			status.Checks[name] = err.Error()
		} else {
			status.Checks[name] = "ok"
		}
	}

	return status
}

func (h *HealthChecker) checkDatabase() error {
	if h.db == nil {
		return nil // No database configured
	}
	return h.db.Ping()
}

func (h *HealthChecker) checkRedis() error {
	if h.redis == nil {
		return nil // No redis configured
	}
	ctx := context.Background()
	return h.redis.Ping(ctx).Err()
}
