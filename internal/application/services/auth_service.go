package services

import (
	"context"
	"errors"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/exceptions"
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/ports/output"
	"time"

	"github.com/google/uuid"
)

type authService struct {
	tokenRepo   output.TokenRepository
	tokenExpiry time.Duration
}

var _ input.AuthService = (*authService)(nil)

func NewAuthService(tokenRepo output.TokenRepository, tokenExpiry time.Duration) input.AuthService {
	return &authService{
		tokenRepo:   tokenRepo,
		tokenExpiry: tokenExpiry,
	}
}

func (s *authService) ValidateToken(ctx context.Context, token string) (*entities.Session, error) {
	session, err := s.tokenRepo.Find(ctx, token)
	if err != nil {
		return nil, errors.New(string(exceptions.ErrInvalidToken))
	}

	if !session.IsActive || session.IsExpired() {
		return nil, errors.New(string(exceptions.ErrSessionExpired))
	}

	return session, nil
}

func (s *authService) CreateSession(ctx context.Context, userID, tenantID string, permissions map[string]interface{}) (*entities.Session, string, error) {
	session := &entities.Session{
		ID:          uuid.New().String(),
		UserID:      userID,
		TenantID:    tenantID,
		Permissions: permissions,
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(s.tokenExpiry),
		IsActive:    true,
	}

	// Generate simple token (in real implementation, use JWT)
	token := uuid.New().String()

	if err := s.tokenRepo.Save(ctx, token, session); err != nil {
		return nil, "", err
	}

	return session, token, nil
}

func (s *authService) InvalidateSession(ctx context.Context, sessionID string) error {
	return s.tokenRepo.DeleteBySessionID(ctx, sessionID)
}

func (s *authService) RefreshSession(ctx context.Context, sessionID string) (*entities.Session, string, error) {
	// This would require a sessionID->token mapping in real implementation
	// For template, we'll create a new session
	return nil, "", errors.New(string(exceptions.ErrNotImplemented))
}
