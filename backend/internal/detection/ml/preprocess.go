package ml

import (
	"math"
	"strings"

	"github.com/smartshieldai-idps/backend/internal/models"
)

// PreprocessData converts agent data into a feature vector for ML processing
func PreprocessData(data models.AgentData) ([]float64, error) {
	features := make([]float64, 0)

	// Extract features from raw data
	if data.RawData != nil {
		// Convert raw data to string for text analysis
		rawStr := string(data.RawData)
		
		// Text-based features
		features = append(features, float64(len(rawStr))) // Length
		features = append(features, float64(strings.Count(rawStr, "error"))) // Error count
		features = append(features, float64(strings.Count(rawStr, "warning"))) // Warning count
	}

	// Extract features from protocol
	if data.Protocol != "" {
		// Convert protocol to numeric value
		protocolMap := map[string]float64{
			"TCP": 1.0,
			"UDP": 2.0,
			"ICMP": 3.0,
			"HTTP": 4.0,
			"HTTPS": 5.0,
			"DNS": 6.0,
		}
		if val, ok := protocolMap[strings.ToUpper(data.Protocol)]; ok {
			features = append(features, val)
		} else {
			features = append(features, 0.0) // Unknown protocol
		}
	}

	// Extract features from severity
	if data.Severity != "" {
		// Convert severity to numeric value
		severityMap := map[string]float64{
			"critical": 1.0,
			"high": 0.75,
			"medium": 0.5,
			"low": 0.25,
			"info": 0.0,
		}
		if val, ok := severityMap[strings.ToLower(data.Severity)]; ok {
			features = append(features, val)
		} else {
			features = append(features, 0.0) // Unknown severity
		}
	}

	// Extract features from event type
	if data.EventType != "" {
		// Convert event type to numeric value based on common patterns
		eventTypeMap := map[string]float64{
			"connection": 1.0,
			"authentication": 2.0,
			"authorization": 3.0,
			"file_access": 4.0,
			"process": 5.0,
			"network": 6.0,
			"system": 7.0,
		}
		eventType := strings.ToLower(data.EventType)
		var eventTypeVal float64
		for key, val := range eventTypeMap {
			if strings.Contains(eventType, key) {
				eventTypeVal = val
				break
			}
		}
		features = append(features, eventTypeVal)
	}

	// Time-based features
	features = append(features, float64(data.Timestamp.Hour())) // Hour of day
	features = append(features, float64(data.Timestamp.Weekday())) // Day of week

	// Normalize features to [0, 1] range
	normalizedFeatures := make([]float64, len(features))
	for i, feature := range features {
		// Skip normalization for already normalized features (e.g., severity)
		if i >= len(features)-2 { // Last two features are time-based
			normalizedFeatures[i] = feature / 24.0 // Normalize hour to [0, 1]
			continue
		}
		
		// Log transform and normalize other features
		if feature > 0 {
			normalizedFeatures[i] = math.Log1p(feature) / 10 // Scale down to [0, 1] range
		}
	}

	return normalizedFeatures, nil
} 