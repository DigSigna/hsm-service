package security

import (
	"hsm-service/internal/domain/ports/output"
	// "hsm-service/internal/domain/valueobjects"
)

type JWTAdapter struct {
	keyRepository output.KeyRepository
}

func NewJWTAdapter(keyRepository output.KeyRepository) *JWTAdapter {
	return &JWTAdapter{
		keyRepository: keyRepository,
	}
}

//	func (a *JWTAdapter) GenerateToken(ctx context.Context, req *output.GenerateTokenRequest) (*output.GenerateTokenResponse, error) {
//		// Implementación de la generación de tokens JWT utilizando el HSM
//	}
//	func (a *JWTAdapter) VerifyToken(ctx context.Context, tokenString string) (bool, error) {
//		// Implementación de la verificación de tokens JWT utilizando el HSM
//	}
