package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// DatabaseConfig configuración para PostgreSQL
type DatabaseConfig struct {
	Host            string
	Port            string
	User            string
	Password        string
	DBName          string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// getEnv retrieves the value of the environment variable named by the key or returns the defaultValue if not set.
func getEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvAsInt retrieves the value of the environment variable as an int or returns the defaultValue if not set or invalid.
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

// RedisConfig configuración para Redis
type RedisConfig struct {
	Address  string
	Password string
	DB       int
}

// HSMConfig configuración para SoftHSMv2
type HSMConfig struct {
	LibraryPath    string
	TokenLabel     string
	Pin            string
	Slot           uint
	SessionTimeout time.Duration
}

func LoadDatabaseConfig() *DatabaseConfig {
	return &DatabaseConfig{
		Host:            getEnv("DB_HOST", "localhost"),
		Port:            getEnv("DB_PORT", "5432"),
		User:            getEnv("DB_USER", "postgres"),
		Password:        getEnv("DB_PASSWORD", "postgres"),
		DBName:          getEnv("DB_NAME", "hsm_service"),
		SSLMode:         getEnv("DB_SSL_MODE", "disable"),
		MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
		MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 25),
		ConnMaxLifetime: time.Duration(getEnvAsInt("DB_CONN_MAX_LIFETIME", 300)) * time.Second,
	}
}

func LoadRedisConfig() *RedisConfig {
	return &RedisConfig{
		Address:  getEnv("REDIS_ADDRESS", "localhost:6379"),
		Password: getEnv("REDIS_PASSWORD", ""),
		DB:       getEnvAsInt("REDIS_DB", 0),
	}
}

func LoadHSMConfig() *HSMConfig {
	return &HSMConfig{
		LibraryPath:    getEnv("HSM_LIBRARY_PATH", "/usr/lib/softhsm/libsofthsm2.so"),
		TokenLabel:     getEnv("HSM_TOKEN_LABEL", "myToken"),
		Pin:            getEnv("HSM_PIN", "1234"),
		Slot:           uint(getEnvAsInt("HSM_SLOT", 0)),
		SessionTimeout: time.Duration(getEnvAsInt("HSM_SESSION_TIMEOUT", 30)) * time.Second,
	}
}

// ConnectionString retorna el string de conexión para PostgreSQL
func (c *DatabaseConfig) ConnectionString() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode)
}
