package middlewares

import (
	"hsm-service/pkg/logger"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func LoggingMiddleware(logger logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		duration := time.Since(start)
		c.Set("duration_ms", duration)
		c.Next()

		logger.Info("HTTP Request",
			zap.Int("status", c.Writer.Status()),
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", query),
			zap.String("ip", c.ClientIP()),
			zap.String("user-agent", c.Request.UserAgent()),
			zap.Duration("duration", duration),
		)
	}
}
