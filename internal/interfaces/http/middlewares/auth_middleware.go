package middlewares

import (
	"hsm-service/internal/domain/ports/input"
	"hsm-service/pkg/logger"
	"net/http"

	"go.uber.org/zap"

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
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}
		session, err := m.authService.ValidateToken(c.Request.Context(), token)
		if err != nil {
			m.logger.Warn("Invalid token", zap.Error(err))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set session in context for downstream handlers
		c.Set("session", session)
		c.Set("tenant_id", session.TenantID)
		c.Next()
	}
}
