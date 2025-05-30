package ml

import (
	"fmt"
	"time"

	"github.com/smartshieldai-idps/backend/internal/models"
)

// PostprocessResult converts model predictions into a DetectionResult
func PostprocessResult(prediction []float64, data models.AgentData) (*DetectionResult, error) {
	if len(prediction) == 0 {
		return nil, fmt.Errorf("empty prediction")
	}

	// Get the anomaly score (first value in prediction)
	anomalyScore := prediction[0]

	// Determine if this is an anomaly based on threshold
	isAnomaly := anomalyScore > 0.5

	// Determine anomaly type based on score and data
	anomalyType := determineAnomalyType(anomalyScore, data)

	// Generate explanation
	explanation := generateExplanation(anomalyScore, anomalyType, data)

	return &DetectionResult{
		IsAnomaly:   isAnomaly,
		Confidence:  anomalyScore,
		AnomalyType: anomalyType,
		Features:    prediction,
		Explanation: explanation,
		Timestamp:   time.Now(),
		SourceData:  data,
	}, nil
}

// determineAnomalyType determines the type of anomaly based on score and data
func determineAnomalyType(score float64, data models.AgentData) string {
	// High confidence anomalies
	if score > 0.8 {
		switch {
		case data.EventType == "authentication" || data.EventType == "authorization":
			return "suspicious_auth"
		case data.EventType == "file_access":
			return "suspicious_file_access"
		case data.EventType == "network":
			return "suspicious_network"
		case data.EventType == "process":
			return "suspicious_process"
		default:
			return "high_severity_anomaly"
		}
	}

	// Medium confidence anomalies
	if score > 0.5 {
		switch {
		case data.Severity == "high" || data.Severity == "critical":
			return "high_severity_event"
		case data.Protocol == "TCP" && data.EventType == "connection":
			return "suspicious_connection"
		default:
			return "medium_severity_anomaly"
		}
	}

	// Low confidence anomalies
	return "low_severity_anomaly"
}

// generateExplanation creates a human-readable explanation of the anomaly
func generateExplanation(score float64, anomalyType string, data models.AgentData) string {
	confidence := "high"
	if score < 0.5 {
		confidence = "low"
	} else if score < 0.8 {
		confidence = "medium"
	}

	baseExplanation := fmt.Sprintf("Detected %s confidence %s", confidence, anomalyType)

	// Add context-specific details
	switch anomalyType {
	case "suspicious_auth":
		return fmt.Sprintf("%s in authentication event from %s", baseExplanation, data.Source)
	case "suspicious_file_access":
		return fmt.Sprintf("%s during file access operation", baseExplanation)
	case "suspicious_network":
		return fmt.Sprintf("%s in network traffic from %s to %s", baseExplanation, data.Source, data.Destination)
	case "suspicious_process":
		return fmt.Sprintf("%s in process execution", baseExplanation)
	case "suspicious_connection":
		return fmt.Sprintf("%s in TCP connection from %s:%s", baseExplanation, data.Source, data.Protocol)
	default:
		return baseExplanation
	}
} 