package request

import (
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// extract X-Correlation-ID
func ExtractCorrelationID(r *http.Request) string {
	correlationID := r.Header.Get("X-Correlation-ID")
	if correlationID == "" {
		correlationID = uuid.New().String()
	}
	return correlationID
}

// ExtractClientIP extrae la IP real del cliente considerando proxies
func ExtractClientIP(r *http.Request) string {
	// 1. Check X-Forwarded-For (load balancers, proxies)
	forwarded := r.Header.Get(headerXForwardedFor)
	if forwarded != "" {
		// X-Forwarded-For puede tener múltiples IPs: client, proxy1, proxy2
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			// La primera IP es el cliente real
			clientIP := strings.TrimSpace(ips[0])
			if isValidIP(clientIP) {
				return clientIP
			}
		}
	}

	// 2. Check X-Real-IP (Nginx, otros proxies)
	realIP := r.Header.Get(headerXRealIP)
	if realIP != "" && isValidIP(realIP) {
		return realIP
	}

	// 3. Fallback a RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Si no tiene puerto, usar directamente
		return r.RemoteAddr
	}
	return host
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ExtractUserAgent extrae el User-Agent
func ExtractUserAgent(r *http.Request) string {
	return r.Header.Get(headerUserAgent)
}

// ExtractRequestID extrae o genera un Request ID
func ExtractRequestID(r *http.Request) string {
	if id := r.Header.Get(headerXRequestID); id != "" {
		return id
	}

	// Si no hay header, podrías generar uno aquí
	// Pero es mejor que el load balancer/ingress lo genere
	return ""
}

// ExtractActor extrae quién hizo la request (API Key, User ID, etc.)
func ExtractActor(r *http.Request) string {
	// 1. API Key header
	if apiKey := r.Header.Get(headerXAPIKey); apiKey != "" {
		// Opcional: hash parcial para logs
		return "api-key:" + maskAPIKey(apiKey)
	}

	// 2. Authorization Bearer token
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			// Hash parcial para logs
			return "jwt:" + maskToken(token)
		}
	}

	// 3. JWT en query param (menos común)
	if token := r.URL.Query().Get("token"); token != "" {
		return "jwt-query:" + maskToken(token)
	}

	return "anonymous"
}

// maskAPIKey oculta parte del API key para logs
func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return "***"
	}
	return apiKey[:4] + "..." + apiKey[len(apiKey)-4:]
}

func maskToken(token string) string {
	if len(token) <= 10 {
		return "***"
	}
	return token[:3] + "..." + token[len(token)-3:]
}
