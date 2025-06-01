package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRedisClient is a mock implementation of the Redis client
type MockRedisClient struct {
	mock.Mock
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	args := m.Called(ctx, key, value, expiration)
	return args.Get(0).(*redis.StatusCmd)
}

func (m *MockRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	args := m.Called(ctx)
	return args.Get(0).(*redis.StatusCmd)
}

// MockElasticClient is a mock implementation of the Elasticsearch client
type MockElasticClient struct {
	mock.Mock
}

func (m *MockElasticClient) Index() *elastic.IndexService {
	args := m.Called()
	return args.Get(0).(*elastic.IndexService)
}

func (m *MockElasticClient) Ping(url string) *elastic.PingService {
	args := m.Called(url)
	return args.Get(0).(*elastic.PingService)
}

func setupTestService() (*XAIService, *MockRedisClient, *MockElasticClient) {
	config := Config{
		BackendURL:   "http://localhost:8080",
		RedisURL:     "localhost:6379",
		ElasticURL:   "http://localhost:9200",
		Port:         "8000",
		ModelVersion: "1.0.0",
	}

	mockRedis := new(MockRedisClient)
	mockElastic := new(MockElasticClient)

	service := &XAIService{
		config:  config,
		redis:   mockRedis,
		elastic: mockElastic,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	return service, mockRedis, mockElastic
}

func setupRouter(service *XAIService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		redisErr := service.redis.Ping(c.Request.Context()).Err()
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

	r.POST("/explain", func(c *gin.Context) {
		var req ExplanationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request format",
			})
			return
		}

		if len(req.InputFeatures) != len(req.FeatureNames) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Number of features and feature names must match",
			})
			return
		}

		explanation := service.generateExplanation(req)

		if err := service.logExplanation(c.Request.Context(), explanation); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to log explanation",
			})
			return
		}

		cacheKey := "explanation:" + req.ModelOutput.ModelVersion
		if err := service.cacheExplanation(c.Request.Context(), cacheKey, explanation); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to cache explanation",
			})
			return
		}

		c.JSON(http.StatusOK, explanation)
	})

	return r
}

func TestHealthCheck(t *testing.T) {
	service, mockRedis, mockElastic := setupTestService()
	router := setupRouter(service)

	// Mock Redis and Elasticsearch responses
	mockRedis.On("Ping", mock.Anything).Return(redis.NewStatusCmd(context.Background()))
	mockElastic.On("Ping", mock.Anything).Return(&elastic.PingService{})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", response["status"])
	assert.True(t, response["redis"].(bool))
	assert.True(t, response["elastic"].(bool))
}

func TestExplainPrediction(t *testing.T) {
	service, mockRedis, mockElastic := setupTestService()
	router := setupRouter(service)

	reqBody := ExplanationRequest{
		ModelOutput: ModelOutput{
			Score:       0.85,
			Confidence:  0.9,
			ModelVersion: "1.0.0",
		},
		InputFeatures: []float64{1.0, 2.0, 3.0},
		FeatureNames:  []string{"feature1", "feature2", "feature3"},
	}
	jsonBody, _ := json.Marshal(reqBody)

	// Mock Redis and Elasticsearch responses
	mockRedis.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(redis.NewStatusCmd(context.Background()))
	mockElastic.On("Index").Return(&elastic.IndexService{})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/explain", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	var response ExplanationResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.Explanation)
	assert.Equal(t, 0.9, response.ConfidenceScore)
	assert.Equal(t, "1.0.0", response.ModelVersion)
	assert.Len(t, response.FeatureImportance, 3)
}

func TestExplainPredictionInvalidInput(t *testing.T) {
	service, _, _ := setupTestService()
	router := setupRouter(service)

	reqBody := ExplanationRequest{
		ModelOutput: ModelOutput{
			Score:       0.85,
			Confidence:  0.9,
			ModelVersion: "1.0.0",
		},
		InputFeatures: []float64{1.0, 2.0},  // Mismatched length
		FeatureNames:  []string{"feature1", "feature2", "feature3"},
	}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/explain", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)
	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Number of features and feature names must match", response["error"])
} 