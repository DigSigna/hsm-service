package dtos

// CreateKeyRequest DTO para creación de clave
type CreateKeyRequest struct {
	Name      string `json:"name" validate:"required,min=1,max=100"`
	Algorithm string `json:"algorithm" validate:"required,oneof=RSA ECDSA Ed25519"`
	KeySize   int    `json:"key_size" validate:"required,min=256,max=4096"`
	TenantID  string `json:"tenant_id" validate:"required,uuid"`
}

// CreateKeyResponse DTO para respuesta de creación
type CreateKeyResponse struct {
	KeyID     string `json:"key_id"`
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	KeySize   int    `json:"key_size"`
	PublicKey string `json:"public_key,omitempty"`
	CreatedAt string `json:"created_at"`
}

// SignDocumentRequest DTO para firmado
type SignDocumentRequest struct {
	KeyID        string          `json:"key_id" validate:"required,uuid"`
	DocumentHash string          `json:"document_hash" validate:"required,base64"`
	TenantID     string          `json:"tenant_id" validate:"required,uuid"`
	Options      *SigningOptions `json:"options,omitempty"`
}

// SigningOptions DTO para opciones de firmado
type SigningOptions struct {
	SignatureFormat string `json:"signature_format" validate:"oneof=RAW DER P7S"`
	HashAlgorithm   string `json:"hash_algorithm" validate:"oneof=SHA256 SHA384 SHA512"`
}

// SignDocumentResponse DTO para respuesta de firmado
type SignDocumentResponse struct {
	Signature string `json:"signature"` // Base64 encoded
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	SignedAt  string `json:"signed_at"`
}
