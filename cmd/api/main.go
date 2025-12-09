package main

import (
	"hsm-service/internal/application/services"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/infrastructure/audit"
	"hsm-service/internal/infrastructure/config"
	"hsm-service/internal/infrastructure/database"
	"hsm-service/internal/infrastructure/hsm"
	"hsm-service/internal/infrastructure/persistence/mysql"
	"hsm-service/internal/interfaces/http/handlers"
	"hsm-service/internal/interfaces/http/middlewares"
	"hsm-service/internal/interfaces/http/routes"
	"hsm-service/pkg/logger"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	// Configuration
	cfg := config.LoadConfig()

	// Logger
	zapLogger := logger.NewZapLogger(cfg.Environment)
	defer zapLogger.Sync()

	// Database
	raw := cfg.Database.ConnectionString
	if raw == "" {
		raw = os.Getenv("DATABASE_URL")
	}
	if raw == "" {
		log.Fatalf("DATABASE_URL not provided")
	}

	dsn, err := database.ParseMySQLConnectionString(raw)
	if err != nil {
		log.Fatalf("Failed to parse DB connection string: %v", err)
	}

	db, err := database.ConnectMySQL(dsn)
	if err != nil {
		log.Fatalf("Failed to initialize DB: %v", err)
	}
	defer db.Close()

	// HSM Client (mock for now to compile)
	hsmClient, err := hsm.NewSoftHSMClient(
		cfg.HSM.LibraryPath,
		cfg.HSM.Pin,
		cfg.HSM.Slot,
	)

	if err != nil {
		log.Fatalf("Error initializing HSM client: %v", err)
	}

	// Repositories
	keyRepo := mysql.NewMySqlKeyRepository(db)
	auditRepo := mysql.NewAuditRepository(db)

	//  CLIENTE DE AUDITORÍA
	var auditClient output.AuditClient
	if cfg.Audit.Enabled && cfg.Audit.BaseURL != "" {
		// Usar cliente REST para producción
		auditClient = audit.NewRestAuditClient(
			cfg.Audit.BaseURL,
			10*time.Second, // timeout
		)
		log.Printf("Audit client configured for: %s", cfg.Audit.BaseURL)
	} else {
		// Usar mock para desarrollo
		auditClient = audit.NewMockAuditClient()
		log.Printf("Using mock audit client for development")
	}
	defer auditClient.Close()

	// Tenant Repo
	var tenantRepo output.TenantRepository = nil

	// Application Services
	keyService := services.NewKeyService(keyRepo, hsmClient, auditClient, tenantRepo)
	auditService := services.NewAuditService(auditRepo)
	signingService := services.NewSigningService(keyRepo, hsmClient)
	// Handlers
	keyHandler := handlers.NewKeyHandler(zapLogger, keyService, signingService)
	auditHandler := handlers.NewAuditHandler(zapLogger, auditService)

	// Middlewares
	authMiddleware := middlewares.NewAuthMiddleware(zapLogger, nil)

	// Router
	router := routes.SetupRouter(&routes.RouterDependencies{
		Logger:         zapLogger,
		KeyHandler:     keyHandler,
		AuditHandler:   auditHandler,
		AuthMiddleware: authMiddleware,
		HSMClient:      hsmClient,
	})

	// Start server
	log.Printf("Server starting on %s", cfg.Server.Address)
	if err := router.Run(cfg.Server.Address); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
