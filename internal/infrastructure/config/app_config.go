package config

import (
	"log"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Environment string
	Database    DatabaseConfig
	Server      ServerConfig
	HSM         HSMConfig
	Redis       RedisConfig
	Audit       AuditConfig
}

type DatabaseConfig struct {
	HSM_DATABASE_CONNECTION_STRING string `mapstructure:"connection_string"`
}

type ServerConfig struct {
	Address string
}

type HSMConfig struct {
	LibraryPath    string        `mapstructure:"library_path"`
	TokenLabel     string        `mapstructure:"token_label"`
	Pin            string        `mapstructure:"pin"`
	Slot           uint          `mapstructure:"slot"`
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
	Enabled bool   `mapstructure:"enabled"`
	BaseURL string `mapstructure:"base_url"`
}

func (c *Config) IsAuditEnabled() bool {
	return c.Audit.Enabled && c.Audit.BaseURL != ""
}

func LoadConfig() *Config {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	// Valores por defecto para desarrollo
	setDefaults()

	// Leer variables de entorno
	viper.AutomaticEnv()
	viper.SetEnvPrefix("HSM")

	// Intentar cargar config.yaml, pero no fallar si no existe
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Config file not found, using environment variables and defaults: %v", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("Unable to decode config into struct: %v", err)
	}

	return &config
}

func setDefaults() {
	// Database - MySQL para Digital Ocean
	viper.SetDefault("database.connection_string", "")

	// Server
	viper.SetDefault("server.address", ":8080")

	// HSM - Configuración para SoftHSM en Minikube
	viper.SetDefault("hsm.library_path", "/usr/lib/softhsm/libsofthsm2.so")
	viper.SetDefault("hsm.token_label", "digsigna-token")
	viper.SetDefault("hsm.pin", "1234")
	viper.SetDefault("hsm.slot", 0)
	viper.SetDefault("hsm.session_timeout", "30s")
	viper.SetDefault("hsm.max_sessions", 10)

	// Redis - Para auditoría temporal
	viper.SetDefault("redis.address", "localhost:6379")
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.audit_stream", "hsm-audit-events")

	// Audit
	viper.SetDefault("audit.enabled", true)
	viper.SetDefault("audit.base_url", "http://audit-service:8080")
}
