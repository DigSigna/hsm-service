package input

import (
	"context"
	"hsm-service/internal/domain/entities"
)

type AuthService interface {
	ValidateToken(ctx context.Context, token string) (*entities.Session, error)
	CreateSession(ctx context.Context, userID, tenantID string, permissions []string) (*entities.Session, string, error)
	InvalidateSession(ctx context.Context, sessionID string) error
	RefreshSession(ctx context.Context, sessionID string) (*entities.Session, string, error)
}
