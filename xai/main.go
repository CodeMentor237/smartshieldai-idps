package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/olivere/elastic/v7"
)

// Configuration
type Config struct {
	BackendURL     string
	RedisURL       string
	ElasticURL     string
	Port           string
	ModelVersion   string
}

// ModelOutput represents the output from the ML model
type ModelOutput struct {
	Score       float64 `json:"score"`
	Confidence  float64 `json:"confidence"`
	ModelVersion string `json:"model_version"`
}

// ExplanationRequest represents the input for explanation generation
type ExplanationRequest struct {
	ModelOutput    ModelOutput `json:"model_output"`
	InputFeatures  []float64   `json:"input_features"`
	FeatureNames   []string    `json:"feature_names"`
}

// ExplanationResponse represents the output of the explanation service
type ExplanationResponse struct {
	Explanation      string             `json:"explanation"`
	FeatureImportance map[string]float64 `json:"feature_importance"`
	ConfidenceScore  float64            `json:"confidence_score"`
	ModelVersion     string             `json:"model_version"`
	Timestamp        time.Time          `json:"timestamp"`
}

// XAIService represents the XAI service with all its dependencies
type XAIService struct {
	config     Config
	redis      *redis.Client
	elastic    *elastic.Client
	httpClient *http.Client
}

// NewXAIService creates a new XAI service instance
func NewXAIService(config Config) (*XAIService, error) {
	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: config.RedisURL,
	})

	// Initialize Elasticsearch client
	elasticClient, err := elastic.NewClient(
		elastic.SetURL(config.ElasticURL),
		elastic.SetSniff(false),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create elasticsearch client: %v", err)
	}

	// Initialize HTTP client with timeout
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	return &XAIService{
		config:     config,
		redis:      redisClient,
		elastic:    elasticClient,
		httpClient: httpClient,
	}, nil
}

// generateExplanation creates a human-readable explanation for the model's prediction
func (s *XAIService) generateExplanation(req ExplanationRequest) ExplanationResponse {
	// Calculate feature importance using a simple heuristic
	featureImportance := make(map[string]float64)
	totalImportance := 0.0

	for i, feature := range req.FeatureNames {
		importance := req.InputFeatures[i] * req.ModelOutput.Score
		featureImportance[feature] = importance
		totalImportance += importance
	}

	// Normalize feature importance
	for feature := range featureImportance {
		featureImportance[feature] /= totalImportance
	}

	// Generate human-readable explanation
	explanation := fmt.Sprintf(
		"The model (version %s) detected an anomaly with %.2f confidence. "+
			"The most significant factors were: ",
		req.ModelOutput.ModelVersion,
		req.ModelOutput.Confidence,
	)

	// Add top 3 most important features to explanation
	count := 0
	for feature, importance := range featureImportance {
		if count < 3 {
			explanation += fmt.Sprintf("%s (%.2f), ", feature, importance)
			count++
		}
	}

	return ExplanationResponse{
		Explanation:      explanation,
		FeatureImportance: featureImportance,
		ConfidenceScore:  req.ModelOutput.Confidence,
		ModelVersion:     req.ModelOutput.ModelVersion,
		Timestamp:        time.Now(),
	}
}

// logExplanation logs the explanation to Elasticsearch
func (s *XAIService) logExplanation(ctx context.Context, explanation ExplanationResponse) error {
	_, err := s.elastic.Index().
		Index("xai-explanations").
		BodyJson(explanation).
		Do(ctx)
	return err
}

// cacheExplanation caches the explanation in Redis
func (s *XAIService) cacheExplanation(ctx context.Context, key string, explanation ExplanationResponse) error {
	data, err := json.Marshal(explanation)
	if err != nil {
		return err
	}
	return s.redis.Set(ctx, key, data, 24*time.Hour).Err()
}

func main() {
	// Load configuration
	config := Config{
		BackendURL:   getEnv("BACKEND_URL", "http://localhost:8080"),
		RedisURL:     getEnv("REDIS_URL", "localhost:6379"),
		ElasticURL:   getEnv("ELASTIC_URL", "http://localhost:9200"),
		Port:         getEnv("PORT", "8000"),
		ModelVersion: getEnv("MODEL_VERSION", "1.0.0"),
	}

	// Initialize XAI service
	service, err := NewXAIService(config)
	if err != nil {
		log.Fatalf("Failed to initialize XAI service: %v", err)
	}

	// Create Gin router
	r := gin.Default()

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		// Check Redis connection
		redisErr := service.redis.Ping(c.Request.Context()).Err()
		// Check Elasticsearch connection
		elasticErr := service.elastic.Ping(c.Request.Context()).Do(c.Request.Context())

		status := "healthy"
		if redisErr != nil || elasticErr != nil {
			status = "degraded"
		}

		c.JSON(http.StatusOK, gin.H{
			"status":  status,
			"redis":   redisErr == nil,
			"elastic": elasticErr == nil,
		})
	})

	// Explanation endpoint
	r.POST("/explain", func(c *gin.Context) {
		var req ExplanationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request format",
			})
			return
		}

		// Validate input
		if len(req.InputFeatures) != len(req.FeatureNames) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Number of features and feature names must match",
			})
			return
		}

		// Generate explanation
		explanation := service.generateExplanation(req)

		// Log explanation to Elasticsearch
		if err := service.logExplanation(c.Request.Context(), explanation); err != nil {
			log.Printf("Failed to log explanation: %v", err)
		}

		// Cache explanation in Redis
		cacheKey := fmt.Sprintf("explanation:%s", req.ModelOutput.ModelVersion)
		if err := service.cacheExplanation(c.Request.Context(), cacheKey, explanation); err != nil {
			log.Printf("Failed to cache explanation: %v", err)
		}

		c.JSON(http.StatusOK, explanation)
	})

	// Start server
	log.Printf("Starting XAI service on port %s", config.Port)
	if err := r.Run(":" + config.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
} 