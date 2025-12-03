package main

import (
	"database/sql"
	"hsm-service/internal/application/services"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/infrastructure/audit"
	"hsm-service/internal/infrastructure/config"
	"hsm-service/internal/infrastructure/hsm"
	"hsm-service/internal/infrastructure/persistence/postgres"
	"hsm-service/internal/interfaces/http/handlers"
	"hsm-service/internal/interfaces/http/middlewares"
	"hsm-service/internal/interfaces/http/routes"
	"hsm-service/pkg/logger"
	"log"
	"time"

	_ "github.com/lib/pq"
)

func main() {
	// Configuration
	cfg := config.LoadConfig()

	// Logger
	zapLogger := logger.NewZapLogger(cfg.Environment)
	defer zapLogger.Sync()

	// Database
	// db, err := sql.Open("postgres", cfg.DatabaseConnectionString())
	// if err != nil {
	// 	log.Fatalf("Failed to connect to database: %v", err)
	// }
	// defer db.Close()

	// // Test database connection
	// if err := db.Ping(); err != nil {
	// 	log.Fatalf("Database ping failed: %v", err)
	// }

	var db *sql.DB
	if cfg.Environment != "development" {
		// db, err := sql.Open("postgres", cfg.Database.PostgreSQLConnectionString())
		// if err != nil {
		// 	log.Fatalf("Failed to connect to database: %v", err)
		// }
		// defer db.Close()

		// if err := db.Ping(); err != nil {
		// 	log.Fatalf("Database ping failed: %v", err)
		// }
		db = nil
	} else {
		zapLogger.Info("Running in development mode - database connection skipped")
		db = nil // o usa un mock
	}

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
	keyRepo := postgres.NewPostgresKeyRepository(db)
	auditRepo := postgres.NewAuditRepository(db)

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
	var tenantReo output.TenantRepository

	// Application Services
	keyService := services.NewKeyService(keyRepo, hsmClient, auditClient, tenantReo)
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
