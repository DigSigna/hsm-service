package output

import (
	"context"
	"hsm-service/internal/domain/entities"
)

type SlotRepository interface {
	GetAllSlots(ctx context.Context) ([]*entities.HSMSlot, error)
	GetSlotByID(ctx context.Context, id string) (*entities.HSMSlot, error)
	CreateSlot(ctx context.Context, slot entities.HSMSlot) error
	UpdateSlot(ctx context.Context, slot entities.HSMSlot) error
	DeleteSlot(ctx context.Context, id string) error

	UpdateSlotNumber(ctx context.Context, slotID string, slotNumber uint) error
	GetSlotsWithTemporaryIDs(ctx context.Context) ([]*entities.HSMSlot, error)
}
