package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hsm-service/internal/domain/entities"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/pkg/request"
	"net/http"
	"time"
)

// implementa output.AuditTransporter
type RestAuditClient struct {
	baseURL string
	client  *http.Client
}

var _ output.AuditTransporter = (*RestAuditClient)(nil)

func NewRestAuditClient(baseURL string) output.AuditTransporter {
	return &RestAuditClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Send implementa output.AuditTransporter
func (c *RestAuditClient) Send(ctx context.Context, event *entities.AuditEvent) error {
	correlationID := request.GetCorrelationID(ctx)
	// Convertir evento a JSON
	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	// Crear request
	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+"/api/v1/events", // Endpoint unificado
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("failed to create audit request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hsm-service/1.0")
	req.Header.Set("X-Correlation-ID", correlationID)
	// Enviar
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send audit event: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("audit service returned status %d", resp.StatusCode)
	}

	return nil
}

// HealthCheck implementa output.AuditTransporter
func (c *RestAuditClient) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("health check failed with status %d", resp.StatusCode)
	}

	return nil
}
