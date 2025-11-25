package main

import (
	"database/sql"
	"log"
	"platform-templates/templates/template-go-gin/internal/application/services"
	"platform-templates/templates/template-go-gin/internal/domain/ports/output"
	"platform-templates/templates/template-go-gin/internal/infrastructure/audit"
	"platform-templates/templates/template-go-gin/internal/infrastructure/config"
	"platform-templates/templates/template-go-gin/internal/infrastructure/hsm"
	"platform-templates/templates/template-go-gin/internal/infrastructure/persistence/postgres"
	"platform-templates/templates/template-go-gin/internal/interfaces/http/handlers"
	"platform-templates/templates/template-go-gin/internal/interfaces/http/middlewares"
	"platform-templates/templates/template-go-gin/internal/interfaces/http/routes"
	"platform-templates/templates/template-go-gin/pkg/logger"
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
		db, err := sql.Open("postgres", cfg.DatabaseConnectionString())
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			log.Fatalf("Database ping failed: %v", err)
		}
	} else {
		zapLogger.Info("Running in development mode - database connection skipped")
		db = nil // o usa un mock
	}

	// HSM Client (mock for now to compile)
	hsmClient := hsm.NewMockHSMClient()

	// Repositories
	keyRepo := postgres.NewPostgresKeyRepository(db)
	auditRepo := postgres.NewAuditRepository(db)

	// 🆕 CLIENTE DE AUDITORÍA
	var auditClient output.AuditClient
	if cfg.AuditService.Enabled && cfg.AuditService.BaseURL != "" {
		// Usar cliente REST para producción
		auditClient = audit.NewRestAuditClient(
			cfg.AuditService.BaseURL,
			10*time.Second, // timeout
		)
		log.Printf("Audit client configured for: %s", cfg.AuditService.BaseURL)
	} else {
		// Usar mock para desarrollo
		auditClient = audit.NewMockAuditClient()
		log.Printf("Using mock audit client for development")
	}
	defer auditClient.Close()

	// Application Services
	keyService := services.NewKeyService(keyRepo, hsmClient, auditClient)
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
	})

	// Start server
	log.Printf("Server starting on %s", cfg.Server.Address)
	if err := router.Run(cfg.Server.Address); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
