package valueobjects

type KeyUsage string

const (
	KeyUsageSigning    KeyUsage = "SIGNING"
	KeyUsageEncryption KeyUsage = "ENCRYPTION"
	KeyUsageBoth       KeyUsage = "BOTH"
)

type KeyType string

const (
	KeyTypeRSA     KeyType = "RSA"
	KeyTypeECDSA   KeyType = "ECDSA"
	KeyTypeUnknown KeyType = "UNKNOWN"
)

// Métodos de utilidad
func (u KeyUsage) IsValid() bool {
	switch u {
	case KeyUsageSigning, KeyUsageEncryption, KeyUsageBoth:
		return true
	default:
		return false
	}
}

func (u KeyUsage) CanSign() bool {
	return u == KeyUsageSigning || u == KeyUsageBoth
}

func (u KeyUsage) CanEncrypt() bool {
	return u == KeyUsageEncryption || u == KeyUsageBoth
}

func (t KeyType) IsValid() bool {
	switch t {
	case KeyTypeRSA, KeyTypeECDSA:
		return true
	default:
		return false
	}
}
