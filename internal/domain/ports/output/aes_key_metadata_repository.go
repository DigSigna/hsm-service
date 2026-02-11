package output

import (
	"context"
	"hsm-service/internal/domain/entities"
)

type AESKeyMetadataRepository interface {
	GetAllMetadata(ctx context.Context) ([]entities.AESKeyMetadata, error)
	GetMetadataByID(ctx context.Context, id string) (*entities.AESKeyMetadata, error)
	CreateMetadata(ctx context.Context, metadata entities.AESKeyMetadata) error
	DeleteMetadata(ctx context.Context, id string) error
	DisableMetadata(ctx context.Context, id string) error
}
