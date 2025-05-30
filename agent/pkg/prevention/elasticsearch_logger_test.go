package prevention

import (
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/stretchr/testify/assert"
)

func TestElasticsearchLogger_LogAction(t *testing.T) {
	// Create test client
	cfg := elasticsearch.Config{
		Addresses: []string{"http://localhost:9200"},
	}
	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		t.Skip("Elasticsearch not available, skipping test")
	}

	// Create logger
	logger := NewElasticsearchLogger(client, "prevention-actions-test")

	// Create test action
	action := Action{
		Type:      "block_ip",
		Target:    "192.168.1.100",
		Reason:    "test block",
		Timestamp: time.Now(),
		Success:   true,
	}

	// Log action
	err = logger.LogAction(action)
	assert.NoError(t, err)

	// Verify action was logged
	actions, err := logger.GetActions(
		action.Timestamp.Add(-time.Minute),
		action.Timestamp.Add(time.Minute),
	)
	assert.NoError(t, err)
	assert.Len(t, actions, 1)
	assert.Equal(t, action.Type, actions[0].Type)
	assert.Equal(t, action.Target, actions[0].Target)
	assert.Equal(t, action.Reason, actions[0].Reason)
	assert.Equal(t, action.Success, actions[0].Success)
}

func TestElasticsearchLogger_GetActions(t *testing.T) {
	// Create test client
	cfg := elasticsearch.Config{
		Addresses: []string{"http://localhost:9200"},
	}
	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		t.Skip("Elasticsearch not available, skipping test")
	}

	// Create logger
	logger := NewElasticsearchLogger(client, "prevention-actions-test")

	// Create test actions
	now := time.Now()
	actions := []Action{
		{
			Type:      "block_ip",
			Target:    "192.168.1.100",
			Reason:    "test block 1",
			Timestamp: now.Add(-time.Hour),
			Success:   true,
		},
		{
			Type:      "terminate_process",
			Target:    "1234",
			Reason:    "test termination",
			Timestamp: now,
			Success:   true,
		},
	}

	// Log actions
	for _, action := range actions {
		err := logger.LogAction(action)
		assert.NoError(t, err)
	}

	// Get actions within time range
	retrieved, err := logger.GetActions(
		now.Add(-2*time.Hour),
		now.Add(time.Hour),
	)
	assert.NoError(t, err)
	assert.Len(t, retrieved, 2)

	// Verify actions are sorted by timestamp (descending)
	assert.Equal(t, actions[1].Type, retrieved[0].Type)
	assert.Equal(t, actions[0].Type, retrieved[1].Type)

	// Get actions outside time range
	retrieved, err = logger.GetActions(
		now.Add(2*time.Hour),
		now.Add(3*time.Hour),
	)
	assert.NoError(t, err)
	assert.Len(t, retrieved, 0)
}

func TestElasticsearchLogger_ErrorHandling(t *testing.T) {
	// Create test client with invalid address
	cfg := elasticsearch.Config{
		Addresses: []string{"http://invalid:9200"},
	}
	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		t.Skip("Failed to create test client, skipping test")
	}

	// Create logger
	logger := NewElasticsearchLogger(client, "prevention-actions-test")

	// Test logging with invalid client
	action := Action{
		Type:      "block_ip",
		Target:    "192.168.1.100",
		Reason:    "test block",
		Timestamp: time.Now(),
		Success:   true,
	}

	err = logger.LogAction(action)
	assert.Error(t, err)

	// Test getting actions with invalid client
	_, err = logger.GetActions(
		time.Now().Add(-time.Hour),
		time.Now(),
	)
	assert.Error(t, err)
} 