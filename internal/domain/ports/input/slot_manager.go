package input

import "context"

type SlotManager interface {
	// InitializeSlot crea un nuevo token HSM en el slot especificado
	InitializeSlot(ctx context.Context, slot uint, tenantID, pin string) error

	// GetAvailableSlots retorna slots que tienen tokens inicializados
	GetAvailableSlots(ctx context.Context) ([]uint, error)

	// DeleteSlot remueve un slot (limpieza)
	DeleteSlot(ctx context.Context, slot uint) error
}
