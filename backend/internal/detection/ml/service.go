package ml

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/smartshieldai-idps/backend/internal/models"
)

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
}

// ModelMetrics tracks model performance metrics
type ModelMetrics struct {
	TotalPredictions    int64     `json:"total_predictions"`
	AnomaliesDetected   int64     `json:"anomalies_detected"`
	LastPredictionTime  time.Time `json:"last_prediction_time"`
	AverageLatency      float64   `json:"average_latency"`
	TotalLatency        float64   `json:"total_latency"`
	Version             string    `json:"version"`
	LastMetricsUpdate   time.Time `json:"last_metrics_update"`
}

// NewService creates a new ML detection service
func NewService(config ModelConfig) (*Service, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Create model directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(config.ModelPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create model directory: %v", err)
	}

	// Initialize model
	model, err := NewModel(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create model: %v", err)
	}

	// Load metrics if they exist
	metrics := &ModelMetrics{
		Version:           "1.0.0",
		LastMetricsUpdate: time.Now(),
	}
	metricsPath := config.ModelPath + ".metrics"
	if data, err := os.ReadFile(metricsPath); err == nil {
		if err := json.Unmarshal(data, metrics); err != nil {
			log.Printf("Warning: failed to load metrics: %v", err)
		}
	}

	return &Service{
		model:     model,
		config:    config,
		ctx:       ctx,
		cancel:    cancel,
		metrics:   metrics,
		version:   metrics.Version,
		modelPath: config.ModelPath,
	}, nil
}

// Start starts the ML detection service
func (s *Service) Start() error {
	// Start metrics update goroutine
	go s.updateMetrics()
	return nil
}

// Stop stops the ML detection service
func (s *Service) Stop() {
	s.cancel()
	_ = s.saveMetrics() // Ignore error on shutdown
}

// Detect performs anomaly detection on the given data
func (s *Service) Detect(data models.AgentData) (*DetectionResult, error) {
	start := time.Now()
	
	s.mu.RLock()
	result, err := s.model.Predict(data)
	s.mu.RUnlock()
	
	if err != nil {
		return nil, err
	}

	// Update metrics
	s.mu.Lock()
	s.metrics.TotalPredictions++
	if result.IsAnomaly {
		s.metrics.AnomaliesDetected++
	}
	latency := time.Since(start).Seconds()
	s.metrics.TotalLatency += latency
	s.metrics.AverageLatency = s.metrics.TotalLatency / float64(s.metrics.TotalPredictions)
	s.metrics.LastPredictionTime = time.Now()
	s.mu.Unlock()

	return result, nil
}

// GetStats returns the current model statistics
func (s *Service) GetStats() ModelConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.model.GetStats()
}

// GetMetrics returns the current model metrics
func (s *Service) GetMetrics() *ModelMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metrics
}

// updateMetrics periodically saves metrics to disk
func (s *Service) updateMetrics() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.saveMetrics()
		}
	}
}

// saveMetrics saves the current metrics to disk
func (s *Service) saveMetrics() error {
	s.mu.RLock()
	metrics := *s.metrics
	s.mu.RUnlock()

	data, err := json.Marshal(metrics)
	if err != nil {
		log.Printf("Warning: failed to marshal metrics: %v", err)
		return err
	}

	metricsPath := s.modelPath + ".metrics"
	if err := os.WriteFile(metricsPath, data, 0644); err != nil {
		log.Printf("Warning: failed to save metrics: %v", err)
		return err
	}
	return nil
}

// CheckVersion checks if a new model version is available
func (s *Service) CheckVersion() (bool, error) {
	// In a real implementation, this would check a remote repository or API
	// For now, we'll just return false
	return false, nil
}

// UpdateModel updates to a new model version
func (s *Service) UpdateModel(newVersion string) error {
	// In a real implementation, this would download and load a new model version
	// For now, we'll just update the version number
	s.mu.Lock()
	s.version = newVersion
	s.metrics.Version = newVersion
	s.mu.Unlock()
	
	return s.saveMetrics()
} 