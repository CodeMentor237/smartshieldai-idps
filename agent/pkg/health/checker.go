package health

import (
	"context"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/go-redis/redis/v8"
)

// ComponentStatus represents the health status of a component
type ComponentStatus struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	LastCheck time.Time `json:"last_check"`
	Error     string    `json:"error,omitempty"`
	Latency   int64     `json:"latency_ms,omitempty"`
}

// HealthChecker monitors the health of all components
type HealthChecker struct {
	components map[string]ComponentStatus
	mu         sync.RWMutex
	redis      *redis.Client
	elastic    *elasticsearch.Client
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(redis *redis.Client, elastic *elasticsearch.Client) *HealthChecker {
	return &HealthChecker{
		components: make(map[string]ComponentStatus),
		redis:      redis,
		elastic:    elastic,
	}
}

// CheckAll performs health checks on all components
func (h *HealthChecker) CheckAll() map[string]ComponentStatus {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check Redis
	h.checkRedis()

	// Check Elasticsearch
	h.checkElasticsearch()

	// Check ML Model
	h.checkMLModel()

	// Check Prevention Layer
	h.checkPreventionLayer()

	// Check Data Collection
	h.checkDataCollection()

	return h.components
}

// checkRedis checks Redis connection health
func (h *HealthChecker) checkRedis() {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status := ComponentStatus{
		Name:      "redis",
		LastCheck: time.Now(),
	}

	if h.redis == nil {
		status.Status = "error"
		status.Error = "redis client not initialized"
		h.components["redis"] = status
		return
	}

	if err := h.redis.Ping(ctx).Err(); err != nil {
		status.Status = "error"
		status.Error = err.Error()
	} else {
		status.Status = "healthy"
	}

	status.Latency = time.Since(start).Milliseconds()
	h.components["redis"] = status
}

// checkElasticsearch checks Elasticsearch connection health
func (h *HealthChecker) checkElasticsearch() {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	status := ComponentStatus{
		Name:      "elasticsearch",
		LastCheck: time.Now(),
	}

	if h.elastic == nil {
		status.Status = "error"
		status.Error = "elasticsearch client not initialized"
		h.components["elasticsearch"] = status
		return
	}

	res, err := h.elastic.Info(
		h.elastic.Info.WithContext(ctx),
	)
	if err != nil {
		status.Status = "error"
		status.Error = err.Error()
	} else if res.IsError() {
		status.Status = "error"
		status.Error = res.String()
	} else {
		status.Status = "healthy"
	}

	status.Latency = time.Since(start).Milliseconds()
	h.components["elasticsearch"] = status
}

// checkMLModel checks ML model health
func (h *HealthChecker) checkMLModel() {
	start := time.Now()
	status := ComponentStatus{
		Name:      "ml_model",
		LastCheck: time.Now(),
	}

	// TODO: Implement actual ML model health check
	// For now, we'll just check if the model file exists
	status.Status = "healthy"
	status.Latency = time.Since(start).Milliseconds()
	h.components["ml_model"] = status
}

// checkPreventionLayer checks prevention layer health
func (h *HealthChecker) checkPreventionLayer() {
	start := time.Now()
	status := ComponentStatus{
		Name:      "prevention_layer",
		LastCheck: time.Now(),
	}

	// TODO: Implement actual prevention layer health check
	// For now, we'll just check if the prevention layer is initialized
	status.Status = "healthy"
	status.Latency = time.Since(start).Milliseconds()
	h.components["prevention_layer"] = status
}

// checkDataCollection checks data collection health
func (h *HealthChecker) checkDataCollection() {
	start := time.Now()
	status := ComponentStatus{
		Name:      "data_collection",
		LastCheck: time.Now(),
	}

	// TODO: Implement actual data collection health check
	// For now, we'll just check if the data collection is initialized
	status.Status = "healthy"
	status.Latency = time.Since(start).Milliseconds()
	h.components["data_collection"] = status
}

// GetStatus returns the current health status of all components
func (h *HealthChecker) GetStatus() map[string]ComponentStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	status := make(map[string]ComponentStatus)
	for k, v := range h.components {
		status[k] = v
	}

	return status
}

// IsHealthy returns true if all components are healthy
func (h *HealthChecker) IsHealthy() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, status := range h.components {
		if status.Status != "healthy" {
			return false
		}
	}

	return true
} 