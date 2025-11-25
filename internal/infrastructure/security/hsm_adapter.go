package security

import (
	// "context"
	"platform-templates/templates/template-go-gin/internal/domain/ports/output"
	"platform-templates/templates/template-go-gin/internal/domain/valueobjects"
)

type HSMAdapter struct {
	keyRepository output.KeyRepository
}

func NewHSMAdapter(keyRepository output.KeyRepository) *HSMAdapter {
	return &HSMAdapter{
		keyRepository: keyRepository,
	}
}

//	func (a *HSMAdapter) GenerateKey(ctx context.Context, req *output.GenerateKeyRequest) (*output.GenerateKeyResponse, error) {
//		// Implementación de la generación de claves utilizando el HSM
//	}
//
//	func (a *HSMAdapter) SignData(ctx context.Context, req *output.SignDataRequest) (*output.SignDataResponse, error) {
//		// Implementación de la firma de datos utilizando el HSM
//	}
//
//	func (a *HSMAdapter) GetPublicKey(ctx context.Context, keyID string) ([]byte, error) {
//		// Implementación para obtener la clave pública desde el HSM
//	}
//
//	func (a *HSMAdapter) DeleteKey(ctx context.Context, keyID string) error {
//		// Implementación para eliminar una clave del HSM
//	}
func mapKeyAlgorithm(algorithm valueobjects.KeyAlgorithm) string {
	switch algorithm {
	case valueobjects.RSA:
		return "RSA"
	case valueobjects.ECDSA:
		return "ECDSA"
	default:
		return "UNKNOWN"
	}
}
