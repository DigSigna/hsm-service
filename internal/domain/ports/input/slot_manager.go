package input

import (
	"context"
	"hsm-service/internal/domain/valueobjects"
)

type SlotManager interface {
	// InitializeSlot crea un nuevo token HSM en el slot especificado
	InitializeSlot(
		ctx context.Context,
		pin string,
		identityContext *valueobjects.IdentityContext,
	) (uint, error)

	// GetAvailableSlots retorna slots que tienen tokens inicializados
	GetAvailableSlots(ctx context.Context) ([]uint, error)
	GetAllSlots(ctx context.Context) ([]uint, error)

	// DeleteSlot remueve un slot (limpieza)
	DeleteSlot(ctx context.Context, slot uint) error
}
