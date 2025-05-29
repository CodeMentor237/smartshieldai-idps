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
func (l *Logger) LogThreat(ctx context.Context, data *models.AgentData, matches []yara.MatchRule) error {
	for _, match := range matches {
		alert := ThreatAlert{
			Timestamp:   time.Now(),
			AgentID:    data.AgentID,
			RuleName:   match.Rule,
			Severity:   getSeverity(match),
			Description: getDescription(match),
			Source:     *data,
		}

		// Add matched strings as match data
		matchData := map[string]interface{}{
			"strings": match.Strings,
			"tags":    match.Tags,
		}
		matchJSON, err := json.Marshal(matchData)
		if err != nil {
			return fmt.Errorf("failed to marshal match data: %v", err)
		}
		alert.MatchData = matchJSON

		// Index the alert
		alertJSON, err := json.Marshal(alert)
		if err != nil {
			return fmt.Errorf("failed to marshal alert: %v", err)
		}

		res, err := l.client.Index(
			l.index,
			bytes.NewReader(alertJSON),
			l.client.Index.WithContext(ctx),
			l.client.Index.WithPipeline("threat-alerts"),
		)
		if err != nil {
			return fmt.Errorf("failed to index alert: %v", err)
		}
		defer res.Body.Close()

		if res.IsError() {
			return fmt.Errorf("error indexing alert: %s", res.String())
		}
	}

	return nil
}

// getSeverity extracts severity from YARA rule metadata
func getSeverity(match yara.MatchRule) string {
	for _, meta := range match.Metas {
		if meta.Identifier == "severity" {
			return meta.Value.(string)
		}
	}
	return "medium" // default severity
}

// getDescription extracts description from YARA rule metadata
func getDescription(match yara.MatchRule) string {
	for _, meta := range match.Metas {
		if meta.Identifier == "description" {
			return meta.Value.(string)
		}
	}
	return fmt.Sprintf("Match found for rule: %s", match.Rule)
}