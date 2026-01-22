package request

import (
	"context"
	"hsm-service/internal/domain/valueobjects"
)

// Definir tipos seguros para keys del contexto
type contextKey string

const (
	// Context keys
	correlationIDKey contextKey = "correlation_id"
	sessionIDKey     contextKey = "session_id"
	ipAddressKey     contextKey = "ip_address"
	userAgentKey     contextKey = "user_agent"
	requestIDKey     contextKey = "request_id"
	actorKey         contextKey = "actor" // API key, user ID, etc.

	identityContextKey contextKey = "identity_context"
	// Headers comunes
	headerXForwardedFor = "X-Forwarded-For"
	headerXRealIP       = "X-Real-IP"
	headerUserAgent     = "User-Agent"
	headerXRequestID    = "X-Request-ID"
	headerXAPIKey       = "X-API-Key"

	duration = "duration_ms"
	tenantID = "tenant_id"
)

// ContextValues contiene todos los valores extraídos del request
type ContextValues struct {
	CorrelationID string
	SessionID     string
	IPAddress     string
	UserAgent     string
	RequestID     string
	Actor         string // API Key o User ID
	Duration      int64
	TenantID      string
}

// WithIdentityContext agrega el identity context al context.Context de Go
func WithIdentityContext(ctx context.Context, identity *valueobjects.IdentityContext) context.Context {
	return context.WithValue(ctx, identityContextKey, identity)
}

// GetIdentityContext extrae el identity context del context.Context
func GetIdentityContext(ctx context.Context) (*valueobjects.IdentityContext, bool) {
	identity, ok := ctx.Value(identityContextKey).(*valueobjects.IdentityContext)
	return identity, ok
}

// MustGetIdentityContext extrae el identity o panic
func MustGetIdentityContext(ctx context.Context) *valueobjects.IdentityContext {
	identity, ok := GetIdentityContext(ctx)
	if !ok {
		panic("identity context not found in context")
	}
	return identity
}

// Funciones para obtener valores del contexto
func GetCorrelationID(ctx context.Context) string {
	if val, ok := ctx.Value(correlationIDKey).(string); ok {
		return val
	}
	return ""
}

func GetSessionID(ctx context.Context) string {
	if val, ok := ctx.Value(sessionIDKey).(string); ok {
		return val
	}
	return ""
}

func IPAddressFromContext(ctx context.Context) string {
	val, _ := ctx.Value(ipAddressKey).(string)
	return val
}

func UserAgentFromContext(ctx context.Context) string {
	val, _ := ctx.Value(userAgentKey).(string)
	return val
}

func RequestIDFromContext(ctx context.Context) string {
	val, _ := ctx.Value(requestIDKey).(string)
	return val
}

func ActorFromContext(ctx context.Context) string {
	val, _ := ctx.Value(actorKey).(string)
	return val
}

func DurationFromContext(ctx context.Context) int64 {
	val, _ := ctx.Value(duration).(int64)
	return val
}

func TenantIDFromContext(ctx context.Context) string {
	val, _ := ctx.Value(tenantID).(string)
	return val
}

func ContextValuesFromContext(ctx context.Context) *ContextValues {
	return &ContextValues{
		CorrelationID: GetCorrelationID(ctx),
		SessionID:     GetSessionID(ctx),
		IPAddress:     IPAddressFromContext(ctx),
		UserAgent:     UserAgentFromContext(ctx),
		RequestID:     RequestIDFromContext(ctx),
		Actor:         ActorFromContext(ctx),
		Duration:      DurationFromContext(ctx),
		TenantID:      TenantIDFromContext(ctx),
	}
}
