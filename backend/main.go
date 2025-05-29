package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	v1 "github.com/smartshieldai-idps/backend/api/v1"
	"github.com/smartshieldai-idps/backend/config"
	"github.com/smartshieldai-idps/backend/internal/detection/elasticsearch"
	"github.com/smartshieldai-idps/backend/internal/detection/rules"
	"github.com/smartshieldai-idps/backend/internal/middleware"
	"github.com/smartshieldai-idps/backend/internal/store"
	"golang.org/x/time/rate"
)

func main() {
	log.Println("Starting SmartShield AI IDPS Backend Server...")

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize Redis store
	dataStore, err := store.NewStore(cfg.RedisURL)
	if err != nil {
		log.Fatalf("Failed to initialize Redis store: %v", err)
	}
	defer dataStore.Close()

	// Initialize YARA rules manager
	rulesDir := filepath.Join("rules")
	rulesManager, err := rules.NewManager(rulesDir)
	if err != nil {
		log.Fatalf("Failed to initialize YARA rules manager: %v", err)
	}
	defer rulesManager.Close()

	// Initialize and start rules update service
	updateService := rules.NewUpdateService(rulesManager, 1*time.Hour)
	updateService.Start()
	defer updateService.Stop()

	// Load YARA rules
	if err := rulesManager.UpdateRules(); err != nil {
		log.Fatalf("Failed to load YARA rules: %v", err)
	}

	// Initialize Elasticsearch logger
	esLogger, err := elasticsearch.NewLogger(
		cfg.ElasticsearchAddrs,
		cfg.ElasticsearchUser,
		cfg.ElasticsearchPass,
		cfg.ElasticsearchIndex,
	)
	if err != nil {
		log.Printf("Warning: failed to initialize Elasticsearch logger: %v", err)
		log.Println("Threat logging to Elasticsearch will be disabled")
	}

	// Initialize Gin router with middleware
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Add recovery, logging, and security middleware
	router.Use(gin.Recovery())
	router.Use(gin.Logger())
	router.Use(middleware.SecurityHeaders())

	// Add rate limiting (100 requests per minute with burst of 10)
	rateLimiter := middleware.NewRateLimiter(rate.Limit(100.0/60.0), 10)
	router.Use(rateLimiter.RateLimit())

	// Add request validation and timeout
	router.Use(middleware.ValidateJSON())
	router.Use(middleware.RequestTimeout(30 * time.Second))

	// Initialize API handlers with all components
	handler := v1.NewHandler(dataStore, rulesManager, esLogger)
	handler.RegisterRoutes(router)

	// Configure TLS
	tlsConfig := config.GetTLSConfig()
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on port %s", cfg.Port)
		if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Create shutdown context with 5 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited successfully")
}