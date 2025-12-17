package request

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type key string

const CorrelationIDKey key = "correlation_id"

// GinMiddleware es el middleware para Gin que extrae metadata
func GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extraer valores del request
		ip := ExtractClientIP(c.Request)
		userAgent := ExtractUserAgent(c.Request)
		actor := ExtractActor(c.Request)

		// Obtener o generar Request ID
		requestID := ExtractRequestID(c.Request)
		if requestID == "" {
			requestID = generateRequestID()
			// Opcional: setear en header de respuesta
			c.Header("X-Request-ID", requestID)
		}

		correlationID := ExtractCorrelationID(c.Request)

		c.Set(string(CorrelationIDKey), correlationID)

		sessionID := c.GetHeader("X-Session-ID")

		// Crear nuevo contexto con los valores
		ctx := c.Request.Context()
		ctx = context.WithValue(ctx, correlationIDKey, correlationID)
		ctx = context.WithValue(ctx, sessionIDKey, sessionID)
		ctx = context.WithValue(ctx, ipAddressKey, ip)
		ctx = context.WithValue(ctx, userAgentKey, userAgent)
		ctx = context.WithValue(ctx, requestIDKey, requestID)
		ctx = context.WithValue(ctx, actorKey, actor)

		// Actualizar el request con el nuevo contexto
		c.Request = c.Request.WithContext(ctx)

		// Continuar
		c.Next()
	}
}

func generateRequestID() string {
	return uuid.New().String()
}

// HTTPMiddleware es para net/http estándar
func HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// extraer session id y correlation id si aplicable
		// Aquí asumimos que vienen en headers, ajustar según necesidad
		correlationID := ExtractCorrelationID(r)

		sessionID := r.Header.Get("X-Session-ID")

		ip := ExtractClientIP(r)
		userAgent := ExtractUserAgent(r)
		actor := ExtractActor(r)
		requestID := ExtractRequestID(r)

		if requestID == "" {
			requestID = generateRequestID()
			w.Header().Set("X-Request-ID", requestID)
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, correlationIDKey, correlationID)
		ctx = context.WithValue(ctx, sessionIDKey, sessionID)
		ctx = context.WithValue(ctx, ipAddressKey, ip)
		ctx = context.WithValue(ctx, userAgentKey, userAgent)
		ctx = context.WithValue(ctx, requestIDKey, requestID)
		ctx = context.WithValue(ctx, actorKey, actor)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
