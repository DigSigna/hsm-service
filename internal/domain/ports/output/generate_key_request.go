package output

type GenerateKeyRequest struct {
	Algorithm string
	KeySize   int
	// Add other fields as needed
}

type GenerateKeyResponse struct {
	KeyID     string
	PublicKey []byte
	// Add other fields as needed
}
