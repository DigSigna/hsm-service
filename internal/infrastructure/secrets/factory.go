package secrets

import (
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
)

type Config struct {
	Strategy valueobjects.AESKeyManagerStrategy
	Local    LocalConfig
	K8S      K8SConfig
	Vault    VaultConfig
}

type LocalConfig struct {
	MasterKeyKey string `yaml:"masterKeyKey"` // Key incide of config (ex: "master-aes-key-v1")
	KeyID        string `yaml:"keyID"`
}

type K8SConfig struct {
	SecretName      string `yaml:"secretName"`
	SecretNamespace string `yaml:"secretNamespace"`
	KeyID           string `yaml:"keyID"`
	MasterKeyKey    string `yaml:"masterKeyKey"`    // Key incide of Secret (ex: "master-aes-key-v2")
	OldMasterKeyKey string `yaml:"oldMasterKeyKey"` // Key incide of Secret for old key (ex: "master-aes-key-v1")
	KubeconfigPath  string `yaml:"kubeconfigPath"`  // Optional: for local development
	InCluster       bool   `yaml:"inCluster"`       // If running inside the cluster
}

type VaultConfig struct {
	Address string
	Token   string
	Path    string
	KeyName string
}

func NewAESKeyManager(
	config Config,
	auditDispatcher output.AuditEventDispatcher,
) (output.AESKeyManager, error) {

	var strategy output.AESKeyManager

	switch config.Strategy {
	case valueobjects.AESKeyManagerStrategyLocal:
		strategy = NewLocalAESKeyManager(config.Local)
	case valueobjects.AESKeyManagerStrategyk8s:
		s, err := NewK8SAESKeyManager(config.K8S)
		if err != nil {
			return nil, err
		}
		strategy = s

	case valueobjects.AESKeyManagerStrategyVault:
		strategy = NewVaultAESKeyManager(config.Vault)
	default:
		strategy = NewLocalAESKeyManager(config.Local)
	}

	return NewAESKeyManagerAdapter(strategy, auditDispatcher), nil
}
