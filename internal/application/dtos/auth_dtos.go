package dtos

// LoginRequest DTO para solicitud de login
type LoginRequest struct {
	UserID      string   `json:"user_id" validate:"required,uuid"`
	TenantID    string   `json:"tenant_id" validate:"required,uuid"`
	Permissions []string `json:"permissions" validate:"required,min=1"`
}

// LoginResponse DTO para respuesta de login
type LoginResponse struct {
	Session   *SessionResponse `json:"session"`
	Token     string           `json:"token"`
	ExpiresAt string           `json:"expires_at"`
}

// SessionResponse DTO para información de sesión
type SessionResponse struct {
	ID          string   `json:"id"`
	UserID      string   `json:"user_id"`
	TenantID    string   `json:"tenant_id"`
	Permissions []string `json:"permissions"`
	CreatedAt   string   `json:"created_at"`
	ExpiresAt   string   `json:"expires_at"`
}

// ValidateTokenRequest DTO para validación de token
type ValidateTokenRequest struct {
	Token string `json:"token" validate:"required,jwt"`
}

// ValidateTokenResponse DTO para respuesta de validación
type ValidateTokenResponse struct {
	Valid      bool     `json:"valid"`
	SessionID  string   `json:"session_id,omitempty"`
	UserID     string   `json:"user_id,omitempty"`
	TenantID   string   `json:"tenant_id,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}