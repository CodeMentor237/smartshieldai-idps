package prevention

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
)

// Logger handles logging prevention actions to Elasticsearch
type Logger struct {
	esClient *elasticsearch.Client
	index    string
}

// NewLogger creates a new prevention action logger
func NewLogger(esClient *elasticsearch.Client, index string) *Logger {
	return &Logger{
		esClient: esClient,
		index:    index,
	}
}

// LogAction logs a prevention action to Elasticsearch
func (l *Logger) LogAction(action Action) error {
	// Add additional context
	action.Context["agent_version"] = "1.0.0"
	action.Context["hostname"] = getHostname()

	// Create document
	doc := map[string]interface{}{
		"@timestamp": action.Timestamp,
		"type":       "prevention_action",
		"action":     action,
	}

	// Marshal to JSON
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal action: %v", err)
	}

	// Index document
	res, err := l.esClient.Index(
		l.index,
		bytes.NewReader(data),
		l.esClient.Index.WithContext(context.Background()),
		l.esClient.Index.WithRefresh("true"),
	)
	if err != nil {
		return fmt.Errorf("failed to index action: %v", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error indexing action: %s", res.String())
	}

	return nil
}

// LogRollback logs a rollback action to Elasticsearch
func (l *Logger) LogRollback(action Action) error {
	// Add additional context
	action.Context["agent_version"] = "1.0.0"
	action.Context["hostname"] = getHostname()
	action.Context["rollback_time"] = time.Now()

	// Create document
	doc := map[string]interface{}{
		"@timestamp": time.Now(),
		"type":       "prevention_rollback",
		"action":     action,
	}

	// Marshal to JSON
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal rollback: %v", err)
	}

	// Index document
	res, err := l.esClient.Index(
		l.index,
		bytes.NewReader(data),
		l.esClient.Index.WithContext(context.Background()),
		l.esClient.Index.WithRefresh("true"),
	)
	if err != nil {
		return fmt.Errorf("failed to index rollback: %v", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error indexing rollback: %s", res.String())
	}

	return nil
}

// getHostname returns the system hostname
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
} 