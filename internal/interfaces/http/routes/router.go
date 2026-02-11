package routes

import (
	"fmt"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/interfaces/http/handlers"
	"hsm-service/internal/interfaces/http/middlewares"
	"hsm-service/pkg/logger"
	"hsm-service/pkg/request"

	"time"

	"github.com/gin-gonic/gin"
)

type RouterDependencies struct {
	Logger         logger.Logger
	KeyHandler     *handlers.KeyHandler
	AuthMiddleware *middlewares.AuthMiddleware
	HSMManager     output.HSMManager
	SlotHandler    *handlers.SlotHandler
}

func SetupRouter(deps *RouterDependencies) *gin.Engine {
	router := gin.New()

	router.Use(request.GinMiddleware())
	// Global middlewares
	router.Use(middlewares.RecoveryMiddleware(deps.Logger))
	router.Use(middlewares.LoggingMiddleware(deps.Logger))
	router.Use(gin.Recovery())

	// Basic health endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":    "healthy",
			"service":   "hsm-service",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	router.GET("/hsm-health", func(c *gin.Context) {
		if deps.HSMManager == nil {
			c.JSON(503, gin.H{
				"status": "HSM client not configured",
				"error":  "HSMClient dependency not injected",
			})
			return
		}

		response := map[string]interface{}{}
		health := deps.HSMManager.HealthCheckAll()

		for slot, healthy := range health {
			if healthy {
				response[fmt.Sprintf("slot_%d", slot)] = "healthy"
			} else {
				response[fmt.Sprintf("slot_%d", slot)] = "unhealthy"
			}
		}
		c.JSON(200, response)
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
		// protected.Use(deps.AuthMiddleware.ValidateToken())
		protected.Use(deps.AuthMiddleware.ValidateJWT())
		{
			// Key management
			keys := protected.Group("/keys")
			{
				keys.POST("", deps.KeyHandler.CreateKey)
				keys.GET("/:tenant_id", deps.KeyHandler.ListKeys)
				keys.POST("/sign", deps.KeyHandler.SignHash)
				keys.POST("/verify", deps.KeyHandler.VerifyHashSignature)
			}
		}
	}

	internal := router.Group("/internal")
	{
		protected := internal.Group("/")
		protected.Use(deps.AuthMiddleware.ValidateJWT())
		{
			hsm := protected.Group("/hsm")
			{
				hsm.POST("/slots/initialize", deps.SlotHandler.InitializeSlot)
				hsm.GET("/slots/available", deps.SlotHandler.GetAvailableSlots)
				hsm.GET("/slots/all", deps.SlotHandler.GetAllSlots)
				hsm.DELETE("/slots/:slot", deps.SlotHandler.DeleteSlot)
			}
		}
	}

	return router
}
