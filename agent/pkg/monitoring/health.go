package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/smartshieldai-idps/agent/config"
)

// HealthStatus represents the health status of the agent
type HealthStatus struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	AgentID   string    `json:"agent_id"`

	// Component health
	Components struct {
		NetworkCapture bool `json:"network_capture"`
		SystemMonitor  bool `json:"system_monitor"`
		BackendSync    bool `json:"backend_sync"`
		MetricsCollector bool `json:"metrics_collector"`
	} `json:"components"`

	// Resource usage
	Resources struct {
		CPUUsage    float64 `json:"cpu_usage"`
		MemoryUsage float64 `json:"memory_usage"`
		DiskUsage   float64 `json:"disk_usage"`
	} `json:"resources"`

	// Last errors
	LastErrors []string `json:"last_errors,omitempty"`
}

// HealthChecker handles health checks
type HealthChecker struct {
	config     *config.Config
	metrics    *Collector
	status     *HealthStatus
	mu         sync.RWMutex
	errorChan  chan error
	stopChan   chan struct{}
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(cfg *config.Config, metrics *Collector) *HealthChecker {
	return &HealthChecker{
		config:    cfg,
		metrics:   metrics,
		status:    &HealthStatus{},
		errorChan: make(chan error, 100),
		stopChan:  make(chan struct{}),
	}
}

// Start begins health checking
func (h *HealthChecker) Start(ctx context.Context) {
	// Start error collector
	go h.collectErrors()

	// Start health check server
	go h.startHealthServer(ctx)

	// Start periodic health checks
	ticker := time.NewTicker(h.config.Monitoring.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-h.stopChan:
			return
		case <-ticker.C:
			h.checkHealth()
		}
	}
}

// Stop stops health checking
func (h *HealthChecker) Stop() {
	close(h.stopChan)
}

// checkHealth performs health checks
func (h *HealthChecker) checkHealth() {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Update timestamp
	h.status.Timestamp = time.Now()
	h.status.AgentID = h.config.AgentID

	// Check component health
	h.checkComponents()

	// Check resource usage
	h.checkResources()

	// Update overall status
	h.updateStatus()
}

// checkComponents checks the health of individual components
func (h *HealthChecker) checkComponents() {
	// Check network capture
	h.status.Components.NetworkCapture = h.checkNetworkCapture()

	// Check system monitor
	h.status.Components.SystemMonitor = h.checkSystemMonitor()

	// Check backend sync
	h.status.Components.BackendSync = h.checkBackendSync()

	// Check metrics collector
	h.status.Components.MetricsCollector = h.checkMetricsCollector()
}

// checkNetworkCapture checks if network capture is working
func (h *HealthChecker) checkNetworkCapture() bool {
	// This would be implemented to check actual network capture status
	// For now, we'll just return true
	return true
}

// checkSystemMonitor checks if system monitoring is working
func (h *HealthChecker) checkSystemMonitor() bool {
	// This would be implemented to check actual system monitoring status
	// For now, we'll just return true
	return true
}

// checkBackendSync checks if backend synchronization is working
func (h *HealthChecker) checkBackendSync() bool {
	// This would be implemented to check actual backend sync status
	// For now, we'll just return true
	return true
}

// checkMetricsCollector checks if metrics collection is working
func (h *HealthChecker) checkMetricsCollector() bool {
	// This would be implemented to check actual metrics collection status
	// For now, we'll just return true
	return true
}

// checkResources checks resource usage
func (h *HealthChecker) checkResources() {
	metrics := h.metrics.GetMetrics()
	h.status.Resources.CPUUsage = metrics.System.CPUUsage
	h.status.Resources.MemoryUsage = metrics.System.MemoryUsage
	h.status.Resources.DiskUsage = metrics.System.DiskUsage
}

// updateStatus updates the overall health status
func (h *HealthChecker) updateStatus() {
	// Check if all components are healthy
	allHealthy := h.status.Components.NetworkCapture &&
		h.status.Components.SystemMonitor &&
		h.status.Components.BackendSync &&
		h.status.Components.MetricsCollector

	// Check resource usage
	resourcesOK := h.status.Resources.CPUUsage < 0.9 &&
		h.status.Resources.MemoryUsage < 0.9 &&
		h.status.Resources.DiskUsage < 0.9

	if allHealthy && resourcesOK {
		h.status.Status = "healthy"
	} else {
		h.status.Status = "degraded"
	}
}

// collectErrors collects errors for health status
func (h *HealthChecker) collectErrors() {
	for {
		select {
		case <-h.stopChan:
			return
		case err := <-h.errorChan:
			h.mu.Lock()
			// Keep only the last 10 errors
			if len(h.status.LastErrors) >= 10 {
				h.status.LastErrors = h.status.LastErrors[1:]
			}
			h.status.LastErrors = append(h.status.LastErrors, err.Error())
			h.mu.Unlock()
		}
	}
}

// startHealthServer starts the health check HTTP server
func (h *HealthChecker) startHealthServer(ctx context.Context) {
	http.HandleFunc("/health", h.handleHealthCheck)
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", h.config.Monitoring.HealthCheckPort),
		Handler: nil,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Health server error: %v", err)
		}
	}()

	<-ctx.Done()
	server.Close()
}

// handleHealthCheck handles health check HTTP requests
func (h *HealthChecker) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.status)
}

// ReportError reports an error to the health checker
func (h *HealthChecker) ReportError(err error) {
	select {
	case h.errorChan <- err:
	default:
		log.Printf("Warning: error channel is full, dropping error: %v", err)
	}
}

// GetStatus returns the current health status
func (h *HealthChecker) GetStatus() *HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.status
} 