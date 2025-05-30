package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartshieldai-idps/agent/pkg/config"
	"github.com/smartshieldai-idps/agent/pkg/health"
	"github.com/smartshieldai-idps/agent/pkg/metrics"
	"github.com/smartshieldai-idps/agent/pkg/prevention"
)

func TestEndToEndFlow(t *testing.T) {
	// Skip if not running integration tests
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Initialize components
	cfg := &config.Config{
		BackendURL: "http://localhost:8080",
		ML: config.MLConfig{
			Enabled:    true,
			ModelPath:  "./models/ml_model.json",
			InputSize:  64,
			HiddenSize: 128,
			BatchSize:  32,
		},
		Prevention: config.PreventionConfig{
			Enabled:            true,
			DryRun:            true,
			ActionTimeout:      time.Second * 5,
			MaxConcurrentActions: 10,
		},
	}

	// Validate configuration
	validator := config.NewConfigValidator(cfg)
	err := validator.Validate()
	require.NoError(t, err)

	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer redisClient.Close()

	// Initialize Elasticsearch client
	esClient, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{"http://localhost:9200"},
	})
	require.NoError(t, err)

	// Initialize health checker
	healthChecker := health.NewHealthChecker(redisClient, esClient)
	status := healthChecker.CheckAll()
	assert.True(t, healthChecker.IsHealthy(), "health check failed: %v", status)

	// Initialize metrics collector
	metricsCollector := metrics.NewMetricsCollector()

	// Initialize prevention layer
	preventionLayer := prevention.NewPreventionLayer(cfg.Prevention.DryRun)

	// Test data collection and ML detection
	t.Run("Data Collection and ML Detection", func(t *testing.T) {
		// Record metrics
		start := time.Now()
		metricsCollector.RecordDataCollection(time.Since(start), nil, false)

		// Simulate ML detection
		start = time.Now()
		metricsCollector.RecordMLDetection(time.Since(start), nil, false, false)

		// Verify metrics
		metrics := metricsCollector.GetMetrics()
		assert.Greater(t, metrics["data_collection"].(map[string]interface{})["count"], uint64(0))
		assert.Greater(t, metrics["ml_detection"].(map[string]interface{})["count"], uint64(0))
	})

	// Test prevention actions
	t.Run("Prevention Actions", func(t *testing.T) {
		// Test IP blocking
		action, err := preventionLayer.BlockIP("192.168.1.100", "test block")
		require.NoError(t, err)
		assert.NotNil(t, action)
		assert.Equal(t, "block_ip", action.Type)
		assert.True(t, action.Success)

		// Record metrics
		start := time.Now()
		metricsCollector.RecordPreventionAction(time.Since(start), nil, false)

		// Verify metrics
		metrics := metricsCollector.GetMetrics()
		assert.Greater(t, metrics["prevention"].(map[string]interface{})["count"], uint64(0))
	})

	// Test storage operations
	t.Run("Storage Operations", func(t *testing.T) {
		ctx := context.Background()

		// Test Redis write
		start := time.Now()
		err := redisClient.Set(ctx, "test_key", "test_value", time.Minute).Err()
		require.NoError(t, err)
		metricsCollector.RecordStorageWrite(time.Since(start), err)

		// Test Redis read
		start = time.Now()
		_, err = redisClient.Get(ctx, "test_key").Result()
		require.NoError(t, err)
		metricsCollector.RecordStorageRead(time.Since(start), err)

		// Test Elasticsearch write
		start = time.Now()
		_, err = esClient.Index(
			"test-index",
			strings.NewReader(`{"test": "value"}`),
			esClient.Index.WithContext(ctx),
		)
		require.NoError(t, err)
		metricsCollector.RecordStorageWrite(time.Since(start), err)

		// Verify metrics
		metrics := metricsCollector.GetMetrics()
		assert.Greater(t, metrics["storage"].(map[string]interface{})["write"].(map[string]interface{})["count"], uint64(0))
		assert.Greater(t, metrics["storage"].(map[string]interface{})["read"].(map[string]interface{})["count"], uint64(0))
	})

	// Test error handling
	t.Run("Error Handling", func(t *testing.T) {
		// Test invalid IP block
		_, err := preventionLayer.BlockIP("invalid-ip", "test block")
		assert.Error(t, err)

		// Record metrics
		start := time.Now()
		metricsCollector.RecordPreventionAction(time.Since(start), err, false)

		// Verify metrics
		metrics := metricsCollector.GetMetrics()
		assert.Greater(t, metrics["prevention"].(map[string]interface{})["errors"], uint64(0))
	})

	// Test cleanup
	t.Run("Cleanup", func(t *testing.T) {
		// Reset metrics
		metricsCollector.Reset()

		// Verify reset
		metrics := metricsCollector.GetMetrics()
		assert.Equal(t, uint64(0), metrics["data_collection"].(map[string]interface{})["count"])
		assert.Equal(t, uint64(0), metrics["ml_detection"].(map[string]interface{})["count"])
		assert.Equal(t, uint64(0), metrics["prevention"].(map[string]interface{})["count"])
	})
} 