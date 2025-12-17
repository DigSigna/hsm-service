package request

import "context"

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

	// Headers comunes
	headerXForwardedFor = "X-Forwarded-For"
	headerXRealIP       = "X-Real-IP"
	headerUserAgent     = "User-Agent"
	headerXRequestID    = "X-Request-ID"
	headerXAPIKey       = "X-API-Key"

	duration = "duration_ms"
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

func ContextValuesFromContext(ctx context.Context) *ContextValues {
	return &ContextValues{
		CorrelationID: GetCorrelationID(ctx),
		SessionID:     GetSessionID(ctx),
		IPAddress:     IPAddressFromContext(ctx),
		UserAgent:     UserAgentFromContext(ctx),
		RequestID:     RequestIDFromContext(ctx),
		Actor:         ActorFromContext(ctx),
		Duration:      DurationFromContext(ctx),
	}
}
