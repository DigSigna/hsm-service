package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"platform-templates/templates/template-go-gin/internal/domain/entities"
	"platform-templates/templates/template-go-gin/internal/domain/ports/output"
	"time"
)

type RestAuditClient struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
}

func NewRestAuditClient(baseURL string, timeout time.Duration) output.AuditClient {
	return &RestAuditClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

func (c *RestAuditClient) LogSecurityEvent(ctx context.Context, event entities.AuditEvent) error {
	return c.sendEvent(ctx, "/api/v1/audit/security", event)
}

func (c *RestAuditClient) LogBusinessEvent(ctx context.Context, event entities.AuditEvent) error {
	return c.sendEvent(ctx, "/api/v1/audit/business", event)
}

func (c *RestAuditClient) LogSystemEvent(ctx context.Context, event entities.AuditEvent) error {
	return c.sendEvent(ctx, "/api/v1/audit/system", event)
}

func (c *RestAuditClient) sendEvent(ctx context.Context, endpoint string, event entities.AuditEvent) error {
	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create audit request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send audit event: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("audit service returned status %d", resp.StatusCode)
	}

	return nil
}

func (c *RestAuditClient) Close() error {
	// Cleanup resources if needed
	return nil
}
