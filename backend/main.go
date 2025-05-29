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
	"github.com/smartshieldai-idps/backend/internal/store"
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
	rulesManager, err := rules.NewManager()
	if err != nil {
		log.Fatalf("Failed to initialize YARA rules manager: %v", err)
	}
	defer rulesManager.Close()

	// Load YARA rules
	ruleFiles, err := filepath.Glob(filepath.Join(cfg.YaraRulesPath, "*.yar"))
	if err != nil {
		log.Fatalf("Failed to find YARA rules: %v", err)
	}

	for _, ruleFile := range ruleFiles {
		if err := rulesManager.AddRuleFile(ruleFile); err != nil {
			log.Printf("Warning: failed to load rule file %s: %v", ruleFile, err)
			continue
		}
	}

	if err := rulesManager.CompileRules(); err != nil {
		log.Fatalf("Failed to compile YARA rules: %v", err)
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

	// Initialize Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

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