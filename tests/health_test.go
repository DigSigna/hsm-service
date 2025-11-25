package tests

import (
	"encoding/json"
	"hsm-service/internal/interfaces/http/routes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestHealthEndpoint(t *testing.T) {
	// Setup
	logger, _ := zap.NewDevelopment()
	router := routes.SetupRouter(&routes.RouterDependencies{
		Logger:         logger,
		KeyHandler:     nil, // Mock para test básico
		AuditHandler:   nil,
		AuthMiddleware: nil,
	})

	// Test health endpoint
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.Equal(t, "healthy", response["status"])
	assert.Equal(t, "template-go-gin", response["service"])
}

func TestReadyEndpoint(t *testing.T) {
	// Setup
	logger, _ := zap.NewDevelopment()
	router := routes.SetupRouter(&routes.RouterDependencies{
		Logger:         logger,
		KeyHandler:     nil,
		AuditHandler:   nil,
		AuthMiddleware: nil,
	})

	// Test ready endpoint
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ready", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.Equal(t, "ready", response["status"])
}
