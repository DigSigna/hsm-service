package middlewares

import (
	"hsm-service/internal/domain/ports/input"
	"hsm-service/pkg/logger"

	// "net/http"
	"hsm-service/internal/domain/entities" //mock
	"strings"                              //mock

	// "go.uber.org/zap"

	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	logger      logger.Logger
	authService input.AuthService
}

func NewAuthMiddleware(logger logger.Logger, authService input.AuthService) *AuthMiddleware {
	return &AuthMiddleware{
		logger:      logger,
		authService: authService,
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
