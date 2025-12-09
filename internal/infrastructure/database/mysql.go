package database

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"os"

	"github.com/go-sql-driver/mysql"
)

func RegisterCustomTLS() error {
	rootCertPool := x509.NewCertPool()
	pem, err := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
	if err != nil {
		return fmt.Errorf("cannot load CA bundle: %w", err)
	}

	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		return fmt.Errorf("failed to append CA")
	}

	return mysql.RegisterTLSConfig("custom", &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCertPool,
	})
}

func ConnectMySQL(dsn string) (*sql.DB, error) {
	// Parsear DSN
	parsedDSN, err := ParseMySQLConnectionString(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Conectar
	db, err := sql.Open("mysql", parsedDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open DB: %v", err)
	}

	// Configurar pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * 60) // 5 minutos

	// Verificar conexión
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping db: %w", err)
	} else {
		fmt.Println("Successfully connected to MySQL database")
	}

	return db, nil
}
