package middlewares

import (
	"hsm-service/internal/domain/ports/input"
	"hsm-service/internal/domain/valueobjects"
	"hsm-service/internal/interfaces/auth"
	"hsm-service/pkg/logger"
	"net/http"

	"hsm-service/internal/domain/entities"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type AuthMiddleware struct {
	logger      logger.Logger
	authService input.AuthService
	validator   *auth.Validator
}

// AuthConfig configuración del middleware
type AuthConfig struct {
	Mode     string `yaml:"mode"`
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	TenantID string `yaml:"tenant_id"`
	UserID   string `yaml:"user_id"`
	OrgID    string `yaml:"org_id"`
}

func NewAuthMiddleware(logger logger.Logger, validator *auth.Validator) *AuthMiddleware {
	return &AuthMiddleware{
		logger:    logger,
		validator: validator,
	}
}

func (m *AuthMiddleware) ValidateJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extraer token del header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.handleUnauthorized(c, "Authorization header required")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		// Modo desarrollo especial
		// if m.config.Mode == "development" {
		// 	m.handleDevelopmentMode(c, tokenString)
		// 	return
		// }

		// Validar token en modo producción
		m.handleProductionMode(c, tokenString)
	}
}

func (m *AuthMiddleware) handleProductionMode(c *gin.Context, tokenString string) {
	// Validar token JWT
	claims, err := m.validator.ValidateToken(tokenString)
	if err != nil {
		m.logger.Warn("Invalid JWT token", zap.Error(err))
		m.handleUnauthorized(c, "Invalid token: "+err.Error())
		return
	}

	// Crear contexto de identidad
	identity := m.createIdentityContext(claims)
	session := m.createSessionContext(claims)

	c.Set("identity_context", identity)
	c.Set("session", session)
	// Establecer en contexto Gin
	c.Set("identity", identity)
	c.Set("tenant_id", identity.TenantID)
	c.Set("owner_id", identity.OwnerID)
	c.Set("organization_id", identity.OrganizationID)

	c.Next()
}

// createIdentityContext crea un IdentityContext desde claims JWT
func (m *AuthMiddleware) createIdentityContext(claims *auth.CustomClaims) *valueobjects.IdentityContext {
	// Determinar OwnerType
	var ownerType valueobjects.OwnerType
	switch claims.OwnerType {
	case "TENANT":
		ownerType = valueobjects.OwnerTypeTenant
	case "USER":
		ownerType = valueobjects.OwnerTypeUser
	case "ORGANIZATION":
		ownerType = valueobjects.OwnerTypeOrganization
	default:
		ownerType = valueobjects.OwnerTypeUser
	}

	return &valueobjects.IdentityContext{
		TenantID:          claims.TenantID,
		OwnerType:         ownerType,
		OwnerID:           claims.OwnerID,
		OrganizationID:    claims.OrganizationID,
		ParentKeyID:       claims.ParentKeyID,
		UserID:            claims.UserID,
		CertLevel:         claims.CertLevel,
		MaxCertLevel:      claims.MaxCertLevel,
		CanCertify:        claims.CanCertify,
		CertificationPath: claims.CertificationPath,
		Permissions:       claims.Permissions,
	}
}

func (m *AuthMiddleware) createSessionContext(claims *auth.CustomClaims) *entities.Session {
	var ownerType valueobjects.OwnerType
	switch claims.OwnerType {
	case "TENANT":
		ownerType = valueobjects.OwnerTypeTenant
	case "USER":
		ownerType = valueobjects.OwnerTypeUser
	case "ORGANIZATION":
		ownerType = valueobjects.OwnerTypeOrganization
	default:
		ownerType = valueobjects.OwnerTypeUser
	}

	return &entities.Session{
		TenantID:          claims.TenantID,
		OwnerType:         ownerType,
		OwnerID:           claims.OwnerID,
		OrganizationID:    claims.OrganizationID,
		ParentKeyID:       claims.ParentKeyID,
		CertLevel:         claims.CertLevel,
		CertificationPath: claims.CertificationPath,
		CanCertify:        claims.CanCertify,
		MaxCertLevel:      claims.MaxCertLevel,
		Permissions:       claims.Permissions,
		TokenID:           claims.ID,
	}
}

func (m *AuthMiddleware) ValidateToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		// En desarrollo, aceptar cualquier token o incluso sin token
		token := c.GetHeader("Authorization")

		// Si no hay token, crear una sesión mock para desarrollo
		if token == "" {
			m.logger.Info("Development mode: using mock session")
			session := &entities.Session{
				ID:       "dev-session",
				UserID:   "dev-user",
				TenantID: "dev-tenant",
				IsActive: true,
			}
			c.Set("session", session)
			c.Set("tenant_id", session.TenantID)
			c.Next()
			return
		}

		// Si hay token, extraer tenant_id del token o header
		if after, ok := strings.CutPrefix(token, "Bearer "); ok {
			token = after
		}

		// Mock session basada en token (puedes extraer tenant_id del token si tiene formato)
		session := &entities.Session{
			ID:       "mock-session",
			UserID:   "mock-user",
			TenantID: extractTenantFromToken(token),
			IsActive: true,
		}

		c.Set("session", session)
		c.Set("tenant_id", session.TenantID)
		c.Next()
	}
}

func extractTenantFromToken(token string) string {
	// Lógica simple para extraer tenant_id del token
	// Por ejemplo, si el token es "tenant123-token", extraer "tenant123"
	if strings.Contains(token, "-") {
		parts := strings.Split(token, "-")
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return "default-tenant"
}

// func (m *AuthMiddleware) ValidateToken() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		token := c.GetHeader("Authorization")
// 		if token == "" {
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
// 			c.Abort()
// 			return
// 		}

// 		// Remove "Bearer " prefix if present
// 		if len(token) > 7 && token[:7] == "Bearer " {
// 			token = token[7:]
// 		}
// 		session, err := m.authService.ValidateToken(c.Request.Context(), token)
// 		if err != nil {
// 			m.logger.Warn("Invalid token", zap.Error(err))
// 			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 			c.Abort()
// 			return
// 		}

// 		// Set session in context for downstream handlers
// 		c.Set("session", session)
// 		c.Set("tenant_id", session.TenantID)
// 		c.Next()
// 	}
// }

// handleUnauthorized maneja respuestas no autorizadas
func (m *AuthMiddleware) handleUnauthorized(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, gin.H{
		"error":   "Unauthorized",
		"message": message,
	})
	c.Abort()
}
