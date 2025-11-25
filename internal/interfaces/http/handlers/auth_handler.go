package handlers

import (
	"hsm-service/pkg/logger"
	"net/http"

	"github.com/gin-gonic/gin"
)

// AuthHandler handles authentication requests
type AuthHandler struct {
	logger logger.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(logger logger.Logger) *AuthHandler {
	return &AuthHandler{
		logger: logger,
	}
}

// Login handles user login
func (h *AuthHandler) Login(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "login endpoint - to be implemented",
	})
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "register endpoint - to be implemented",
	})
}
