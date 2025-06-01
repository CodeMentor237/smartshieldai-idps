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
	"github.com/smartshieldai-idps/xai/pkg/xai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRedisClient is a mock implementation of the Redis client
type MockRedisClient struct {
	mock.Mock
	*redis.Client // Embed redis.Client to satisfy interface
}

func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	args := m.Called(ctx, key, value, expiration)
	return args.Get(0).(*redis.StatusCmd)
}

func (m *MockRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	args := m.Called(ctx)
	return args.Get(0).(*redis.StatusCmd)
}

func (m *MockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	args := m.Called(ctx, key)
	return args.Get(0).(*redis.StringCmd)
}

func (m *MockRedisClient) Keys(ctx context.Context, pattern string) *redis.StringSliceCmd {
	args := m.Called(ctx, pattern)
	return args.Get(0).(*redis.StringSliceCmd)
}

func (m *MockRedisClient) Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd {
	args := m.Called(ctx, cursor, match, count)
	return args.Get(0).(*redis.ScanCmd)
}

func setupTestHandler() (*xai.Handler, *MockRedisClient) {
	mockRedis := &MockRedisClient{
		Client: redis.NewClient(&redis.Options{
			Addr: "localhost:6379",
		}),
	}
	handler := xai.NewHandler(mockRedis)
	return handler, mockRedis
}

func setupRouter(handler *xai.Handler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	handler.RegisterRoutes(r)
	return r
}

func TestHealthCheck(t *testing.T) {
	handler, mockRedis := setupTestHandler()
	router := setupRouter(handler)

	// Mock Redis ping response
	mockRedis.On("Ping", mock.Anything).Return(redis.NewStatusCmd(context.Background()))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/xai/health", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "healthy", response["status"])
	assert.True(t, response["redis"].(bool))
}

func TestExplainPrediction(t *testing.T) {
	handler, mockRedis := setupTestHandler()
	router := setupRouter(handler)

	reqBody := xai.ExplanationRequest{
		ModelOutput: xai.ModelOutput{
			Score:        0.85,
			Confidence:   0.9,
			ModelVersion: "1.0.0",
		},
		InputFeatures: []float64{1.0, 2.0, 3.0},
		FeatureNames:  []string{"feature1", "feature2", "feature3"},
	}
	jsonBody, _ := json.Marshal(reqBody)

	// Mock Redis responses
	mockRedis.On("Set", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(redis.NewStatusCmd(context.Background()))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/xai/explain", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotNil(t, response["id"])
	assert.NotNil(t, response["explanation"])

	explanation := response["explanation"].(map[string]interface{})
	assert.NotEmpty(t, explanation["explanation"])
	assert.Equal(t, 0.9, explanation["confidence_score"])
	assert.Equal(t, "1.0.0", explanation["model_version"])
	assert.Len(t, explanation["feature_importance"], 3)
}

func TestExplainPredictionInvalidInput(t *testing.T) {
	handler, _ := setupTestHandler()
	router := setupRouter(handler)

	reqBody := xai.ExplanationRequest{
		ModelOutput: xai.ModelOutput{
			Score:        0.85,
			Confidence:   0.9,
			ModelVersion: "1.0.0",
		},
		InputFeatures: []float64{1.0, 2.0}, // Mismatched length
		FeatureNames:  []string{"feature1", "feature2", "feature3"},
	}
	jsonBody, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/xai/explain", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Number of features and feature names must match", response["error"])
} 