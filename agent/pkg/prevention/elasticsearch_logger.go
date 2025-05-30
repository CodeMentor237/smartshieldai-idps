package prevention

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
)

// ElasticsearchLogger handles logging prevention actions to Elasticsearch
type ElasticsearchLogger struct {
	client    *elasticsearch.Client
	indexName string
}

// NewElasticsearchLogger creates a new Elasticsearch logger
func NewElasticsearchLogger(client *elasticsearch.Client, indexName string) *ElasticsearchLogger {
	return &ElasticsearchLogger{
		client:    client,
		indexName: indexName,
	}
}

// LogAction logs a prevention action to Elasticsearch
func (l *ElasticsearchLogger) LogAction(action Action) error {
	// Create document for Elasticsearch
	doc := map[string]interface{}{
		"type":       action.Type,
		"target":     action.Target,
		"reason":     action.Reason,
		"timestamp":  action.Timestamp,
		"success":    action.Success,
		"rolled_back": action.RolledBack,
		"error":      action.Error,
	}

	// Convert document to JSON
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal action: %v", err)
	}

	// Index document in Elasticsearch
	res, err := l.client.Index(
		l.indexName,
		bytes.NewReader(data),
		l.client.Index.WithContext(context.Background()),
		l.client.Index.WithRefresh("true"),
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

// GetActions retrieves prevention actions from Elasticsearch
func (l *ElasticsearchLogger) GetActions(startTime, endTime time.Time) ([]Action, error) {
	// Create query
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{
					"gte": startTime.Format(time.RFC3339),
					"lte": endTime.Format(time.RFC3339),
				},
			},
		},
		"sort": []map[string]interface{}{
			{
				"timestamp": map[string]interface{}{
					"order": "desc",
				},
			},
		},
	}

	// Convert query to JSON
	data, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %v", err)
	}

	// Search in Elasticsearch
	res, err := l.client.Search(
		l.client.Search.WithContext(context.Background()),
		l.client.Search.WithIndex(l.indexName),
		l.client.Search.WithBody(bytes.NewReader(data)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to search actions: %v", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("error searching actions: %s", res.String())
	}

	// Parse response
	var result map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Extract hits
	hits, ok := result["hits"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format")
	}

	hitsArray, ok := hits["hits"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid hits format")
	}

	// Convert hits to actions
	actions := make([]Action, 0, len(hitsArray))
	for _, hit := range hitsArray {
		hitMap, ok := hit.(map[string]interface{})
		if !ok {
			continue
		}

		source, ok := hitMap["_source"].(map[string]interface{})
		if !ok {
			continue
		}

		action := Action{
			Type:      source["type"].(string),
			Target:    source["target"].(string),
			Reason:    source["reason"].(string),
			Success:   source["success"].(bool),
			RolledBack: source["rolled_back"].(bool),
		}

		if err, ok := source["error"].(string); ok {
			action.Error = err
		}

		if ts, ok := source["timestamp"].(string); ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				action.Timestamp = t
			}
		}

		actions = append(actions, action)
	}

	return actions, nil
} 