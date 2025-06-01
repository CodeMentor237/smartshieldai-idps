// Package ml provides machine learning capabilities for the IDPS
package ml

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// ModelMonitor handles real-time monitoring of ML model performance
type ModelMonitor struct {
	metrics        *MetricsCollector
	driftDetector  *DriftDetector
	config         *ModelConfig
	alertChan      chan Alert
	stopChan       chan struct{}
	mu            sync.RWMutex
}

// MetricsCollector collects and aggregates model performance metrics
type MetricsCollector struct {
	predictions    []float64
	groundTruth    []float64
	latencies      []time.Duration
	windowSize     int
	mu            sync.RWMutex
}

// DriftDetector monitors for concept drift in the model
type DriftDetector struct {
	referenceData  []float64
	currentData    []float64
	driftThreshold float64
	windowSize     int
	mu            sync.RWMutex
}

// Alert represents a monitoring alert
type Alert struct {
	Type      AlertType
	Message   string
	Severity  AlertSeverity
	Timestamp time.Time
	Metrics   map[string]float64
}

type AlertType string
type AlertSeverity string

const (
	AlertTypeDrift       AlertType = "DRIFT"
	AlertTypePerformance AlertType = "PERFORMANCE"
	AlertTypeError       AlertType = "ERROR"

	AlertSeverityLow    AlertSeverity = "LOW"
	AlertSeverityMedium AlertSeverity = "MEDIUM"
	AlertSeverityHigh   AlertSeverity = "HIGH"
)

// NewModelMonitor creates a new model monitor
func NewModelMonitor(config *ModelConfig) *ModelMonitor {
	return &ModelMonitor{
		metrics: &MetricsCollector{
			windowSize: 1000,
			predictions: make([]float64, 0, 1000),
			groundTruth: make([]float64, 0, 1000),
			latencies: make([]time.Duration, 0, 1000),
		},
		driftDetector: &DriftDetector{
			windowSize: 1000,
			driftThreshold: config.DriftThreshold,
			referenceData: make([]float64, 0, 1000),
			currentData: make([]float64, 0, 1000),
		},
		config:    config,
		alertChan: make(chan Alert, 100),
		stopChan:  make(chan struct{}),
	}
}

// Start begins monitoring the model
func (m *ModelMonitor) Start(ctx context.Context) {
	go m.monitorLoop(ctx)
}

// Stop stops the monitoring
func (m *ModelMonitor) Stop() {
	close(m.stopChan)
}

// RecordPrediction records a new prediction and its ground truth
func (m *ModelMonitor) RecordPrediction(prediction float64, groundTruth float64, latency time.Duration) {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()

	m.metrics.predictions = append(m.metrics.predictions, prediction)
	m.metrics.groundTruth = append(m.metrics.groundTruth, groundTruth)
	m.metrics.latencies = append(m.metrics.latencies, latency)

	// Maintain window size
	if len(m.metrics.predictions) > m.metrics.windowSize {
		m.metrics.predictions = m.metrics.predictions[1:]
		m.metrics.groundTruth = m.metrics.groundTruth[1:]
		m.metrics.latencies = m.metrics.latencies[1:]
	}

	// Update drift detector
	m.driftDetector.mu.Lock()
	m.driftDetector.currentData = append(m.driftDetector.currentData, prediction)
	if len(m.driftDetector.currentData) > m.driftDetector.windowSize {
		m.driftDetector.currentData = m.driftDetector.currentData[1:]
	}
	m.driftDetector.mu.Unlock()
}

// monitorLoop runs continuous monitoring
func (m *ModelMonitor) monitorLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.checkMetrics()
			m.checkDrift()
		}
	}
}

// checkMetrics analyzes current model performance
func (m *ModelMonitor) checkMetrics() {
	m.metrics.mu.RLock()
	defer m.metrics.mu.RUnlock()

	if len(m.metrics.predictions) < 100 {
		return // Not enough data
	}

	accuracy := calculateAccuracy(m.metrics.predictions, m.metrics.groundTruth)

	if accuracy < m.config.MinAccuracy {
		m.alertChan <- Alert{
			Type:     AlertTypePerformance,
			Message:  fmt.Sprintf("Model accuracy below threshold: %.2f < %.2f", accuracy, m.config.MinAccuracy),
			Severity: AlertSeverityHigh,
			Timestamp: time.Now(),
			Metrics: map[string]float64{
				"accuracy": accuracy,
				"threshold": m.config.MinAccuracy,
			},
		}
	}
}

// checkDrift detects concept drift
func (m *ModelMonitor) checkDrift() {
	m.driftDetector.mu.RLock()
	defer m.driftDetector.mu.RUnlock()

	if len(m.driftDetector.currentData) < m.driftDetector.windowSize {
		return // Not enough data
	}

	drift := calculateKLDivergence(m.driftDetector.referenceData, m.driftDetector.currentData)

	if drift > m.driftDetector.driftThreshold {
		m.alertChan <- Alert{
			Type:     AlertTypeDrift,
			Message:  fmt.Sprintf("Model drift above threshold: %.2f > %.2f", drift, m.driftDetector.driftThreshold),
			Severity: AlertSeverityHigh,
			Timestamp: time.Now(),
			Metrics: map[string]float64{
				"drift": drift,
				"threshold": m.driftDetector.driftThreshold,
			},
		}
	}
}

// GetAlerts returns and clears current alerts
func (m *ModelMonitor) GetAlerts() []Alert {
	var alerts []Alert
	for {
		select {
		case alert := <-m.alertChan:
			alerts = append(alerts, alert)
		default:
			return alerts
		}
	}
}

// Helper functions for metric calculations

func calculateAccuracy(predictions, groundTruth []float64) float64 {
	if len(predictions) != len(groundTruth) {
		return 0
	}

	correct := 0
	for i := range predictions {
		if predictions[i] == groundTruth[i] {
			correct++
		}
	}

	return float64(correct) / float64(len(predictions))
}

func calculateAverageLatency(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}

	var total time.Duration
	for _, l := range latencies {
		total += l
	}

	return total / time.Duration(len(latencies))
}

func calculateKLDivergence(p, q []float64) float64 {
	if len(p) != len(q) {
		return math.MaxFloat64
	}

	var divergence float64
	for i := range p {
		if p[i] > 0 && q[i] > 0 {
			divergence += p[i] * math.Log(p[i]/q[i])
		}
	}

	return divergence
}
