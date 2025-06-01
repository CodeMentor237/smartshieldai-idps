package ml

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/smartshieldai-idps/backend/internal/models"
)

// ModelMetrics tracks model performance metrics
type ModelMetrics struct {
	TotalPredictions    int64     `json:"total_predictions"`
	AnomaliesDetected   int64     `json:"anomalies_detected"`
	LastPredictionTime  time.Time `json:"last_prediction_time"`
	AverageLatency      float64   `json:"average_latency"`
	TotalLatency        float64   `json:"total_latency"`
	Version             string    `json:"version"`
	LastMetricsUpdate   time.Time `json:"last_metrics_update"`
	// Additional monitoring metrics
	FalsePositives      int64     `json:"false_positives"`
	FalseNegatives      int64     `json:"false_negatives"`
	Accuracy            float64   `json:"accuracy"`
	F1Score            float64   `json:"f1_score"`
	DriftScore         float64   `json:"drift_score"`
	LastDriftCheck     time.Time `json:"last_drift_check"`
}

// Service manages the ML detection service
type Service struct {
	model     Model
	config    ModelConfig
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
	metrics   *ModelMetrics
	version   string
	modelPath string
	// Model versioning
	modelVersions []string
	// Monitoring
	monitor   *ModelMonitor
	// Prevention handler
	preventionHandler PreventionHandler
}

// NewService creates a new ML detection service
func NewService(config ModelConfig) (*Service, error) {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Service{
		config:    config,
		ctx:       ctx,
		cancel:    cancel,
		metrics:   &ModelMetrics{},
		monitor:   NewModelMonitor(&config),
	}

	// Load pre-trained model
	model, err := NewPretrainedModel(config)
	if err != nil {
		return nil, fmt.Errorf("failed to load pre-trained model: %v", err)
	}

	s.model = model
	s.version = config.Version
	s.modelPath = config.ModelPath

	return s, nil
}

// Start starts the ML service and monitoring
func (s *Service) Start() error {
	s.monitor.Start(s.ctx)
	return nil
}

// Stop stops the service and its monitoring
func (s *Service) Stop() {
	s.monitor.Stop()
	s.cancel()
}

// Predict performs anomaly detection and updates monitoring metrics
func (s *Service) Predict(data models.AgentData) (*DetectionResult, error) {
	start := time.Now()
	
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Make prediction
	result, err := s.model.Predict(data)
	if err != nil {
		return nil, fmt.Errorf("prediction failed: %v", err)
	}

	latency := time.Since(start)

	// Update metrics
	s.updateMetrics(result, latency)

	// Record prediction for monitoring
	s.monitor.RecordPrediction(result.Confidence, 0, latency)

	// Handle prevention if needed
	if result.IsAnomaly && s.preventionHandler != nil {
		if err := s.handlePrevention(result); err != nil {
			log.Printf("Error handling prevention action: %v", err)
		}
	}

	return result, nil
}

// updateMetrics updates service metrics after a prediction
func (s *Service) updateMetrics(result *DetectionResult, latency time.Duration) {
	s.metrics.TotalPredictions++
	s.metrics.LastPredictionTime = time.Now()
	s.metrics.TotalLatency += float64(latency.Milliseconds())
	s.metrics.AverageLatency = s.metrics.TotalLatency / float64(s.metrics.TotalPredictions)
	s.metrics.LastMetricsUpdate = time.Now()

	if result.IsAnomaly {
		s.metrics.AnomaliesDetected++
	}
}

// UpdateWithGroundTruth updates metrics with ground truth data
func (s *Service) UpdateWithGroundTruth(result *DetectionResult, isActualAnomaly bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if result.IsAnomaly && !isActualAnomaly {
		s.metrics.FalsePositives++
	} else if !result.IsAnomaly && isActualAnomaly {
		s.metrics.FalseNegatives++
	}

	total := float64(s.metrics.TotalPredictions)
	if total > 0 {
		truePos := float64(s.metrics.AnomaliesDetected - s.metrics.FalsePositives)
		trueNeg := float64(total - float64(s.metrics.AnomaliesDetected) - float64(s.metrics.FalseNegatives))
		s.metrics.Accuracy = (truePos + trueNeg) / total

		// Calculate F1 score
		precision := truePos / float64(s.metrics.AnomaliesDetected)
		recall := truePos / (truePos + float64(s.metrics.FalseNegatives))
		if precision+recall > 0 {
			s.metrics.F1Score = 2 * (precision * recall) / (precision + recall)
		}
	}

	// Update monitoring with ground truth
	groundTruth := 0.0
	if isActualAnomaly {
		groundTruth = 1.0
	}
	s.monitor.RecordPrediction(result.Confidence, groundTruth, 0)
}

// GetMetrics returns current model metrics
func (s *Service) GetMetrics() *ModelMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metrics
}

// GetConfig returns the current configuration of the ML service
func (s *Service) GetConfig() ModelConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// handlePrevention determines if prevention action is needed and takes it
func (s *Service) handlePrevention(result *DetectionResult) error {
	if !result.IsAnomaly || s.preventionHandler == nil {
		return nil
	}

	// Only take prevention action for high-confidence detections
	if result.Confidence < 0.9 {
		return nil
	}

	action := PreventionAction{
		Confidence: result.Confidence,
		Timestamp:  time.Now(),
		Reason:     result.Explanation,
		Data:       result,
	}

	// Determine action type based on anomaly type
	// Extract target from source data based on anomaly type
	switch result.AnomalyType {
	case "suspicious_network", "suspicious_connection":
		action.Type = "block_ip"
		action.Target = result.SourceData.Source // Use the Source field for IP
	case "suspicious_process":
		action.Type = "terminate_process"
		action.Target = result.SourceData.ProcessID
	default:
		return nil // No prevention action for other types
	}

	return s.preventionHandler.TakeAction(action)
}

// PreventionAction represents an action to be taken by the prevention layer
type PreventionAction struct {
	Type       string      `json:"type"`       // "block_ip", "terminate_process", etc.
	Target     string      `json:"target"`     // IP address, process ID, etc.
	Confidence float64     `json:"confidence"` // ML model confidence score
	Reason     string      `json:"reason"`     // Human-readable explanation
	Timestamp  time.Time   `json:"timestamp"`
	Data       interface{} `json:"data"`       // Additional context
}

// PreventionHandler interface for the prevention layer
type PreventionHandler interface {
	TakeAction(action PreventionAction) error
}

// AddPreventionHandler adds a prevention handler to the service
func (s *Service) AddPreventionHandler(handler PreventionHandler) {
	s.preventionHandler = handler
}