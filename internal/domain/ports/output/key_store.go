package output

// KeyStore port for key storage operations
type KeyStore interface {
    GenerateKey(keyID string, keyType string) error
    GetKey(keyID string) ([]byte, error)
    DeleteKey(keyID string) error
    ListKeys() ([]string, error)
}