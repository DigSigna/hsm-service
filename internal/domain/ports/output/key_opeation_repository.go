package output

import (
	"context"
	"hsm-service/internal/domain/entities"
)

type KeyOperationRepository interface {
	Save(ctx context.Context, key entities.KeyOperation) error
}
