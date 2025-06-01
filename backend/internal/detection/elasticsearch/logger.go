// Package elasticsearch provides Elasticsearch integration for logging
package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/hillu/go-yara/v4"
	"github.com/smartshieldai-idps/backend/internal/models"
)

// ThreatAlert represents a detected threat
type ThreatAlert struct {
	Timestamp   time.Time         `json:"timestamp"`
	AgentID     string           `json:"agent_id"`
	RuleName    string           `json:"rule_name"`
	Severity    string           `json:"severity"`
	Description string           `json:"description"`
	MatchData   json.RawMessage  `json:"match_data"`
	Source      models.AgentData `json:"source_data"`
}

// PreventionAction represents a prevention action taken
type PreventionAction struct {
	Type      string                 `json:"type"`
	Target    string                 `json:"target"`
	Timestamp time.Time             `json:"timestamp"`
	Success   bool                   `json:"success"`
	Error     string                 `json:"error,omitempty"`
	Reason    string                 `json:"reason"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Logger handles logging threats to Elasticsearch
type Logger struct {
	client *elasticsearch.Client
	index  string
}

// NewLogger creates a new Elasticsearch logger
func NewLogger(addresses []string, username, password, index string) (*Logger, error) {
	cfg := elasticsearch.Config{
		Addresses: addresses,
		Username:  username,
		Password:  password,
	}

	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Elasticsearch client: %v", err)
	}

	return &Logger{
		client: client,
		index:  index,
	}, nil
}

// LogThreat logs a detected threat to Elasticsearch
func (l *Logger) LogThreat(alert ThreatAlert) error {
	// Marshal alert to JSON
	alertJSON, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %v", err)
	}

	// Index the alert
	res, err := l.client.Index(
		l.index,
		bytes.NewReader(alertJSON),
		l.client.Index.WithContext(context.Background()),
		l.client.Index.WithRefresh("true"),
		l.client.Index.WithPipeline("threat-alerts"),
	)
	if err != nil {
		return fmt.Errorf("failed to index alert: %v", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error indexing alert: %s", res.String())
	}

	return nil
}

// LogPreventionAction logs a prevention action to Elasticsearch
func (l *Logger) LogPreventionAction(action PreventionAction) error {
	// Marshal action to JSON
	actionJSON, err := json.Marshal(action)
	if err != nil {
		return fmt.Errorf("failed to marshal prevention action: %v", err)
	}

	// Index the action
	res, err := l.client.Index(
		fmt.Sprintf("%s-prevention", l.index),
		bytes.NewReader(actionJSON),
		l.client.Index.WithContext(context.Background()),
		l.client.Index.WithRefresh("true"),
	)
	if err != nil {
		return fmt.Errorf("failed to index prevention action: %v", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("error indexing prevention action: %s", res.String())
	}

	return nil
}

// Helper functions to extract metadata from YARA matches
func getSeverity(match yara.MatchRule) string {
	for _, meta := range match.Metas {
		if meta.Identifier == "severity" {
			if sev, ok := meta.Value.(string); ok {
				return sev
			}
		}
	}
	return "medium" // Default severity
}

func getDescription(match yara.MatchRule) string {
	for _, meta := range match.Metas {
		if meta.Identifier == "description" {
			if desc, ok := meta.Value.(string); ok {
				return desc
			}
		}
	}
	return fmt.Sprintf("Matched rule: %s", match.Rule)
}