package routes

import (
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/interfaces/http/handlers"
	"hsm-service/internal/interfaces/http/middlewares"
	"hsm-service/pkg/logger"

	"time"

	"github.com/gin-gonic/gin"
)

type RouterDependencies struct {
	Logger         logger.Logger
	KeyHandler     *handlers.KeyHandler
	AuditHandler   *handlers.AuditHandler
	AuthMiddleware *middlewares.AuthMiddleware
	HSMClient      output.HSMClient
}

func SetupRouter(deps *RouterDependencies) *gin.Engine {
	router := gin.New()

	// Global middlewares
	router.Use(middlewares.RecoveryMiddleware(deps.Logger))
	router.Use(middlewares.LoggingMiddleware(deps.Logger))
	router.Use(gin.Recovery())

	// Basic health endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":    "healthy",
			"service":   "template-go-gin",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	router.GET("/hsm-health", func(c *gin.Context) {
		if deps.HSMClient == nil {
			c.JSON(503, gin.H{
				"status": "HSM client not configured",
				"error":  "HSMClient dependency not injected",
			})
			return
		}

		if err := deps.HSMClient.HealthCheck(c.Request.Context()); err != nil {
			c.JSON(503, gin.H{
				"status": "HSM unhealthy",
				"error":  err.Error(),
			})
			return
		}

		c.JSON(200, gin.H{"status": "HSM healthy"})
	})

	router.GET("/ready", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ready"})
	})

	// API v1 routes
	api := router.Group("/api/v1")
	{
		// Public routes
		public := api.Group("/public")
		{
			public.GET("/keys/:key_id/public-key", deps.KeyHandler.GetPublicKey)
		}

		// Protected routes
		protected := api.Group("/")
		protected.Use(deps.AuthMiddleware.ValidateToken())
		{
			// Key management
			keys := protected.Group("/keys")
			{
				keys.POST("", deps.KeyHandler.CreateKey)
				keys.GET("/:tenant_id", deps.KeyHandler.ListKeys)
				keys.POST("/sign", deps.KeyHandler.SignHash)
			}

			// Audit routes - Agregar estas rutas
			audit := protected.Group("/audit")
			{
				audit.POST("/log", deps.AuditHandler.LogAudit)
				audit.GET("/events", deps.AuditHandler.GetAuditEvents)
			}
		}
	}

	return router
}
