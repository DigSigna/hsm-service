package output

import (
	"context"
	"platform-templates/templates/template-go-gin/internal/domain/entities"
)

type TokenRepository interface {
	Save(ctx context.Context, token string, session *entities.Session) error
	Find(ctx context.Context, token string) (*entities.Session, error)
	Delete(ctx context.Context, token string) error
	DeleteBySessionID(ctx context.Context, sessionID string) error
}