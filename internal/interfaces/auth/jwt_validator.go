package auth

import (
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// CustomClaims estructura de claims personalizada
type CustomClaims struct {
	TenantID          string                 `json:"tenant_id"`
	OwnerType         string                 `json:"owner_type"`
	OwnerID           string                 `json:"owner_id"`
	OrganizationID    *string                `json:"organization_id"`
	ParentKeyID       *string                `json:"parent_key_id,omitempty"`
	UserID            string                 `json:"user_id"`
	CertLevel         int                    `json:"cert_level"`
	MaxCertLevel      int                    `json:"max_cert_level"`
	CanCertify        bool                   `json:"can_certify"`
	CertificationPath string                 `json:"certification_path"`
	Permissions       map[string]interface{} `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

// Validator valida tokens JWT
type Validator struct {
	keyManager *KeyManager
	issuer     string
	audience   string
}

// NewValidator crea un nuevo validador
func NewValidator(keyManager *KeyManager, issuer, audience string) *Validator {
	return &Validator{
		keyManager: keyManager,
		issuer:     issuer,
		audience:   audience,
	}
}

// ValidateToken valida un token JWT y retorna los claims
func (v *Validator) ValidateToken(tokenString string) (*CustomClaims, error) {
	// Parsear el token con claims personalizados
	token, err := jwt.ParseWithClaims(
		tokenString,
		&CustomClaims{},
		v.keyManager.GetKeyFunc(),
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims structure")
	}

	// Validaciones adicionales
	if err := v.validateClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// validateClaims realiza validaciones adicionales de claims
func (v *Validator) validateClaims(claims *CustomClaims) error {
	// Validar issuer
	if claims.Issuer != v.issuer {
		return fmt.Errorf("invalid issuer: expected %s, got %s", v.issuer, claims.Issuer)
	}

	// Validar audience
	audienceValid := slices.Contains(claims.Audience, v.audience)

	if !audienceValid {
		return fmt.Errorf("token not intended for this audience: %s", v.audience)
	}

	// Validar fechas
	now := time.Now()
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(now) {
		return fmt.Errorf("token expired at %v", claims.ExpiresAt.Time)
	}
	if claims.NotBefore != nil && claims.NotBefore.Time.After(now) {
		return fmt.Errorf("token not valid until %v", claims.NotBefore.Time)
	}

	// Validar campos requeridos
	if claims.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if claims.OwnerID == "" {
		return fmt.Errorf("owner_id is required")
	}

	return nil
}
