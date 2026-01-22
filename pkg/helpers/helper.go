package helpers

import (
	"math/big"
	"strings"
)

// GenerateTenantSlotLabel genera una etiqueta única para un tenant basado en su ID.
// La etiqueta es una versión en base36 del UUID del tenant, prefijada con "t-".
// La longitud máxima de la etiqueta es de 32 caracteres.
func GenerateTenantSlotLabel(tenantID string) string {
	// Remover guiones del UUID
	hex := strings.ReplaceAll(tenantID, "-", "")

	// Convertir a base36
	i := new(big.Int)
	i.SetString(hex, 16)
	base36 := i.Text(36)

	// Prefijo + base36 (máximo 27 chars)
	label := "t-" + base36

	// Truncar si excede 32 (por seguridad)
	if len(label) > 32 {
		label = label[:32]
	}

	return label
}
