package valueobjects

type AESKeyManagerStrategy string

const (
	AESKeyManagerStrategyLocal AESKeyManagerStrategy = "local"
	AESKeyManagerStrategyk8s   AESKeyManagerStrategy = "k8s"
	AESKeyManagerStrategyVault AESKeyManagerStrategy = "vault"
)

func (s AESKeyManagerStrategy) IsValid() bool {
	switch s {
	case AESKeyManagerStrategyLocal, AESKeyManagerStrategyk8s, AESKeyManagerStrategyVault:
		return true
	default:
		return false
	}
}
