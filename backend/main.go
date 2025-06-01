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
	"github.com/smartshieldai-idps/backend/internal/detection/ml"
	"github.com/smartshieldai-idps/backend/internal/detection/prevention"
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

	// Initialize ML detection service if enabled
	var mlService *ml.Service
	if cfg.Detection.ML.Enabled {
		mlConfig := ml.ModelConfig{
			// Model architecture
			InputSize:      cfg.Detection.ML.InputSize,
			HiddenSize:     cfg.Detection.ML.HiddenSize,
			NumLayers:      cfg.Detection.ML.NumLayers,
			DropoutRate:    cfg.Detection.ML.DropoutRate,
			
			// Training parameters
			LearningRate:   cfg.Detection.ML.LearningRate,
			BatchSize:      cfg.Detection.ML.BatchSize,
			Epochs:         cfg.Detection.ML.Epochs,
			
			// Model metadata
			ModelPath:      cfg.Detection.ML.ModelPath,
			Version:        "1.0.0", // Initial version
			LastUpdated:    time.Now(),

			// Performance thresholds
			MinAccuracy:    cfg.Detection.ML.MinAccuracy,
			DriftThreshold: cfg.Detection.ML.DriftThreshold,
			FalsePositive:  cfg.Detection.ML.MaxFalsePositive,
			FalseNegative:  cfg.Detection.ML.MaxFalseNegative,

			// CNN specific parameters
			ConvFilters:    128,
			ConvKernelSize: 3,
			PoolingSize:    2,

			// BiLSTM specific parameters
			BidirectionalLayers: 2,
			LSTMDropoutRate:     0.2,
		}

		mlService, err = ml.NewService(mlConfig)
		if err != nil {
			log.Printf("Warning: failed to initialize ML detection service: %v", err)
			log.Println("ML-based detection will be disabled")
		} else {
			// Set up prevention integration if enabled
			if cfg.Prevention.Enabled {
				rollbackTimeout, err := time.ParseDuration(cfg.Prevention.RollbackTimeout)
				if err != nil {
					log.Printf("Warning: invalid rollback timeout %q, using default", cfg.Prevention.RollbackTimeout)
					rollbackTimeout = 30 * time.Second
				}
				
				preventionCfg := prevention.Config{
					EnableBlockIP:     cfg.Prevention.EnableBlockIP,
					EnableProcessKill: cfg.Prevention.EnableProcessKill,
					WhitelistedIPs:   cfg.Prevention.WhitelistedIPs,
					WhitelistedProcs: cfg.Prevention.WhitelistedProcs,
					RollbackTimeout:  rollbackTimeout,
					ESAddrs:         cfg.ElasticsearchAddrs,
					ESUser:          cfg.ElasticsearchUser,
					ESPass:          cfg.ElasticsearchPass,
					ESIndex:         cfg.ElasticsearchIndex,
					LogActions:      true,
					AlertThreshold:  0.9, // High confidence required for prevention actions
				}
				preventionHandler := prevention.NewHandler(preventionCfg)
				mlService.AddPreventionHandler(preventionHandler)
				log.Println("Prevention layer integrated with ML detection")
			}
			
			if err := mlService.Start(); err != nil {
				log.Printf("Warning: failed to start ML detection service: %v", err)
				log.Println("ML-based detection will be disabled")
				mlService = nil
			} else {
				log.Printf("ML detection service started successfully with CNN-BiLSTM model v%s", mlService.GetMetrics().Version)
			}
			defer mlService.Stop()
		}
	}

	// Initialize Gin router with middleware
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Add recovery, logging, and security middleware
	router.Use(middleware.Recovery())
	router.Use(middleware.Logger())
	router.Use(middleware.Security())
	router.Use(middleware.RequestTimeout(30 * time.Second))
	router.Use(middleware.RateLimit(rate.NewLimiter(rate.Limit(cfg.Security.RateLimit), cfg.Security.RateLimitBurst)))

	// Initialize API handler
	handler := v1.NewHandler(dataStore, rulesManager, esLogger, mlService)
	handler.RegisterRoutes(router)

	// Start server
	srv := &http.Server{
		Addr:    ":" + cfg.Server.Port,
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown
	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}