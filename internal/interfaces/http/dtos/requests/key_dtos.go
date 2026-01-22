package requests

type CreateKeyRequest struct {
	Name      string `json:"name" binding:"required,min=1,max=100"`
	Algorithm string `json:"algorithm" binding:"required,oneof=RSA ECDSA Ed25519"`
	KeySize   int    `json:"key_size" binding:"required,min=256,max=4096"`
	Usage     string `json:"usage" binding:"required,oneof=SIGNING ENCRYPTION"`
}

type SignHashRequest struct {
	KeyID    string `json:"key_id" binding:"required,uuid"`
	Hash     string `json:"hash" binding:"required,base64"`
	TenantID string `json:"tenant_id" binding:"required,uuid"`
}
