package config

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Environment   string
	Database      DatabaseConfig
	Server        ServerConfig
	HSM           HSMConfig
	Redis         RedisConfig
	Audit         AuditConfig
	AESKeyManager AESKeyManager
}

type DatabaseConfig struct {
	ConnectionString string `mapstructure:"connection_string"`
}

type ServerConfig struct {
	Address string
}

type HSMConfig struct {
	LibraryPath    string        `mapstructure:"library_path"`
	TokenLabel     string        `mapstructure:"token_label"`
	Pin            string        `mapstructure:"pin"`
	Slot           uint          `mapstructure:"slot"`
	NoSlots        uint          `mapstructure:"no_slots"`
	SessionTimeout time.Duration `mapstructure:"session_timeout"`
	MaxSessions    int           `mapstructure:"max_sessions"`
}

type RedisConfig struct {
	Address     string `mapstructure:"address"`
	Password    string `mapstructure:"password"`
	DB          int    `mapstructure:"db"`
	AuditStream string `mapstructure:"audit_stream"`
}

type AuditConfig struct {
	Enabled  bool                  `mapstructure:"enabled"`
	Strategy string                `mapstructure:"strategy"`
	HTTP     AuditHTTPClientConfig `mapstructure:"http"`
	Hybrid   AuditHybridConfig     `mapstructure:"hybrid"`
}

type AuditStrategy string

const (
	StrategyDatabase AuditStrategy = "database"
	StrategyHTTP     AuditStrategy = "http"
	StrategyHybrid   AuditStrategy = "hybrid"
	StrategyMock     AuditStrategy = "mock"
	StrategyAsync    AuditStrategy = "async"
)

type AuditHTTPClientConfig struct {
	Timeout time.Duration `mapstructure:"timeout"`
	BaseURL string        `mapstructure:"base_url"`
}

type AuditHybridConfig struct {
	CircuitBreaker CircuitBreakerConfig `mapstructure:"circuit_breaker"`
}

type CircuitBreakerConfig struct {
	MaxFailures  int           `mapstructure:"max_failures"`
	ResetTimeout time.Duration `mapstructure:"reset_timeout"`
}

type AESKeyManager struct {
	Strategy string      `mapstructure:"strategy"`
	Local    LocalConfig `mapstructure:"local"`
	K8S      K8SConfig   `mapstructure:"k8s"`
	Vault    VaultConfig `mapstructure:"vault"`
}

type LocalConfig struct {
	MasterKey string `mapstructure:"master_key"`
	KeyID     string `mapstructure:"key_id"`
}
type K8SConfig struct {
	SecretName      string `mapstructure:"secret_name"`
	SecretNamespace string `mapstructure:"secret_namespace"`
	KeyID           string `mapstructure:"key_id"`
	MasterKeyKey    string `mapstructure:"master_key_key"`
	OldMasterKeyKey string `mapstructure:"old_master_key_key"`
	KubeconfigPath  string `mapstructure:"kubeconfig_path"`
	InCluster       bool   `mapstructure:"in_cluster"`
}

type VaultConfig struct {
	Address    string `mapstructure:"address"`
	Token      string `mapstructure:"token"`
	SecretPath string `mapstructure:"secret_path"`
	Path       string `mapstructure:"path"`
	KeyName    string `mapstructure:"key_name"`
}

func (c *Config) IsAuditEnabled() bool {
	return c.Audit.Enabled
}

func LoadConfig() *Config {
	// Obtener el entorno actual
	env := os.Getenv("HSM_ENVIRONMENT")
	if env == "" {
		env = "development"
	}

	// viper.SetConfigName("config")
	// viper.SetConfigType("yaml")
	// viper.AddConfigPath(".")
	// viper.AddConfigPath("./config")
	// viper.AddConfigPath("/app/config") // Para Docker

	// Leer variables de entorno
	viper.AutomaticEnv()
	viper.SetEnvPrefix("HSM")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// IMPORTANTE: Para Digital Ocean Database Cluster
	// Manejar la URL de conexión de manera específica
	viper.BindEnv("database.connection_string", "DATABASE_URL", "HSM_DATABASE_CONNECTION_STRING")

	// // Intentar cargar configuración según entorno
	// configFileName := fmt.Sprintf("config.%s", env)
	// viper.SetConfigName(configFileName)

	// // Intentar cargar archivo de configuración
	// if err := viper.ReadInConfig(); err != nil {
	// 	log.Printf("Config file not found, using environment variables and defaults: %v", err)
	// }

	// Valores por defecto
	setDefaults()

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("Unable to decode config into struct: %v", err)
	}

	// Validar configuración crítica
	if config.Database.ConnectionString == "" {
		log.Fatalf("Database connection string is required. Set DATABASE_URL or HSM_DATABASE_CONNECTION_STRING")
	}

	return &config
}

func setDefaults() {
	// Database - MySQL para Digital Ocean T-ODO TOMAR DEL ENV Y REVISAR ERROR DE CERTIFICADO
	//2025/12/03 23:56:44 Failed to initialize DB: failed to ping db: tls: failed to verify certificate: x509: certificate signed by unknown authority
	// viper.SetDefault("database.connection_string", "DATABASE_URL")

	// Server
	viper.SetDefault("server.address", ":8080")

	// HSM - Configuración para SoftHSM en Minikube
	viper.SetDefault("hsm.library_path", "/usr/lib/softhsm/libsofthsm2.so")
	viper.SetDefault("hsm.token_label", "digsigna-token")
	viper.SetDefault("hsm.pin", "1234")
	viper.SetDefault("hsm.slot", 0)
	viper.SetDefault("hsm.no_slots", 4)
	viper.SetDefault("hsm.session_timeout", "30s")
	viper.SetDefault("hsm.max_sessions", 10)

	// Redis - Para auditoría temporal
	viper.SetDefault("redis.address", "localhost:6379")
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.audit_stream", "hsm-audit-events")

	// Audit
	viper.SetDefault("audit.enabled", true)
	viper.SetDefault("audit.strategy", "hybrid")
	viper.SetDefault("audit.http.base_url", "http://audit-service:8080")
	viper.SetDefault("audit.http.timeout", "5s")
	viper.SetDefault("audit.hybrid.circuit_breaker.max_failures", 5)
	viper.SetDefault("audit.hybrid.circuit_breaker.reset_timeout", "30s")

	// AES Key Manager
	viper.SetDefault("aeskeymanager.strategy", "local")
	viper.SetDefault("aeskeymanager.local.master_key", "LLvxgXPJCEY1sek2eTNihV7laqAIVdQVxz11eYcA8oU=") // "mock_master_key_for_development" en base64
	viper.SetDefault("aeskeymanager.local.key_id", "master-aes-key-v1")
}
