package main

import (
	"context"
	"database/sql"
	"fmt"
	"hsm-service/internal/application/services"
	"hsm-service/internal/domain/ports/output"
	"hsm-service/internal/domain/valueobjects"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"hsm-service/internal/infrastructure/audit"
	"hsm-service/internal/infrastructure/config"
	"hsm-service/internal/infrastructure/database"
	"hsm-service/internal/infrastructure/hsm"
	"hsm-service/internal/infrastructure/storage/mysql"
	"hsm-service/internal/interfaces/http/handlers"
	"hsm-service/internal/interfaces/http/middlewares"
	"hsm-service/internal/interfaces/http/routes"
	"hsm-service/pkg/logger"
	"log"
	"os"

	// "time"

	_ "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
)

func main() {
	// Configuration
	cfg := config.LoadConfig()

	// Logger
	zapLogger := logger.NewZapLogger(cfg.Environment)
	defer zapLogger.Sync()

	// Database
	db, err := initializeDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize DB: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			zapLogger.Error("Failed to close database", zap.Error(err))
		}
		zapLogger.Info("Database connection closed")
	}()

	dbStorage := mysql.NewMySQLAuditStorage(db)

	// Crear audit recorder usando factory
	auditRecorder, err := audit.NewAuditRecorder(
		valueobjects.AuditStrategy(cfg.Audit.Strategy),
		dbStorage,
		cfg.Audit.HTTP.BaseURL, // Puede estar vacío
	)
	if err != nil {
		log.Fatal("Failed to create audit recorder:", err)
	}

	auditDispatcher := audit.NewAuditWorker(auditRecorder)
	defer func() {
		if err := auditDispatcher.Close(); err != nil {
			zapLogger.Error("Failed to close audit worker", zap.Error(err))
		}
		zapLogger.Info("Audit worker closed")
	}()

	// Crear manager HSM
	hsmManager, err := initializeHSM(cfg, auditDispatcher, zapLogger)

	if err != nil {
		log.Fatalf("Failed to create HSM manager: %v", err)
	}
	defer func() {
		if err := hsmManager.CloseAll(); err != nil {
			zapLogger.Error("Failed to close HSM manager", zap.Error(err))
		}
		zapLogger.Info("HSM manager closed")
	}()

	// Crear clientes HSM para cada slot (0-3 para MVP)

	// Repositories
	keyStorage := mysql.NewMySQLKeyStorage(db)
	tenantStorage := mysql.NewMySQLTenantStorage(db)

	// Application Services
	keyService := services.NewKeyService(keyStorage, hsmManager, auditDispatcher, tenantStorage)
	// call hsm key service if needed
	// hsmKeyService := services.NewHSMKeyService(hsmManager, keyStorage, auditDispatcher, tenantStorage)
	signingService := services.NewSigningService(keyStorage, hsmManager, auditDispatcher, tenantStorage)
	slotService := services.NewSlotService(hsmManager, tenantStorage, auditDispatcher, &cfg.HSM)
	// Handlers
	keyHandler := handlers.NewKeyHandler(zapLogger, keyService, signingService)
	slotHandler := handlers.NewSlotHandler(slotService)
	// Middlewares
	authMiddleware := middlewares.NewAuthMiddleware(zapLogger, nil)

	// Router
	router := routes.SetupRouter(&routes.RouterDependencies{
		Logger:         zapLogger,
		KeyHandler:     keyHandler,
		AuthMiddleware: authMiddleware,
		HSMManager:     hsmManager,
		SlotHandler:    slotHandler,
	})

	// Setup HTTP server with timeouts
	srv := &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Channel to listen for errors coming from the listener.
	err = runServerWithTimeouts(cfg, srv, zapLogger)
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// initializeDatabase initializes the database connection using the provided configuration.
func initializeDatabase(cfg *config.Config) (*sql.DB, error) {
	raw := cfg.Database.ConnectionString
	if raw == "" {
		raw = os.Getenv("DATABASE_URL")
	}
	if raw == "" {
		return nil, fmt.Errorf("DATABASE_URL not provided")
	}

	dsn, err := database.ParseMySQLConnectionString(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DB connection string: %v", err)
	}

	db, err := database.ConnectMySQL(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DB: %v", err)
	}
	return db, nil
}

// initializeHSM initializes the HSM manager with clients for each slot.
func initializeHSM(cfg *config.Config, auditDispatcher output.AuditEventDispatcher, zapLogger *logger.ZapLogger) (*hsm.HSMManager, error) {
	hsmManager := hsm.NewHSMManager(auditDispatcher)

	// Crear clientes HSM para cada slot (0-3 para MVP)
	clientsCreated := 0
	for slot := uint(0); slot < 4; slot++ {
		hsmClient, err := hsm.NewSoftHSMClient(
			cfg.HSM.LibraryPath,
			cfg.HSM.Pin,
			slot, // Slot específico
			auditDispatcher,
		)

		if err != nil {
			// Para MVP, podemos continuar si algunos slots fallan
			zapLogger.Error("Failed to create HSM client for slot",
				zap.Uint("slot", slot),
				zap.Error(err))
			continue
		}

		hsmManager.RegisterClient(int(slot), hsmClient)
		clientsCreated++
	}

	if clientsCreated == 0 {
		zapLogger.Error("No HSM clients were created successfully")
		return nil, fmt.Errorf("no HSM clients were created successfully")
	}

	zapLogger.Info("HSM clients initialized", zap.Int("count", clientsCreated))
	return hsmManager, nil
}

// Run server with timeouts and graceful shutdown
func runServerWithTimeouts(cfg *config.Config, srv *http.Server, zapLogger *logger.ZapLogger) error {
	// Channel to listen for errors coming from the listener.
	serverErrors := make(chan error, 1)

	// Start the server in a goroutine
	go func() {
		zapLogger.Info("Server starting", zap.String("address", cfg.Server.Address))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrors <- err
		}
	}()

	// Channel to listen for interrupt or terminate signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Blocking main and waiting for shutdown.
	select {
	case err := <-serverErrors:
		zapLogger.Error("Server failed to start", zap.Error(err))

	case <-shutdown:
		zapLogger.Info("Start shutdown...")

		// Give outstanding requests 30 seconds to complete
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Asking listener to shut down and shed load.
		if err := srv.Shutdown(ctx); err != nil {
			zapLogger.Error("Graceful shutdown did not complete",
				zap.Error(err),
				zap.Duration("timeout", 30*time.Second))

			// Force close if graceful shutdown fails
			if err := srv.Close(); err != nil {
				zapLogger.Error("Force shutdown failed", zap.Error(err))
			}
		}

		zapLogger.Info("Shutdown complete")
	}
	return nil
}
