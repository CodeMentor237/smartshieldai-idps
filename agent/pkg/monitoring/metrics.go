package monitoring

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/smartshieldai-idps/agent/config"
)

// Metrics represents collected metrics
type Metrics struct {
	Timestamp time.Time `json:"timestamp"`
	AgentID   string    `json:"agent_id"`

	// Network metrics
	Network struct {
		PacketsReceived  uint64 `json:"packets_received"`
		PacketsDropped   uint64 `json:"packets_dropped"`
		PacketsFiltered  uint64 `json:"packets_filtered"`
		BytesReceived    uint64 `json:"bytes_received"`
		ActiveConnections int    `json:"active_connections"`
	} `json:"network"`

	// System metrics
	System struct {
		CPUUsage    float64 `json:"cpu_usage"`
		MemoryUsage float64 `json:"memory_usage"`
		DiskUsage   float64 `json:"disk_usage"`
		ProcessCount int     `json:"process_count"`
	} `json:"system"`

	// Agent metrics
	Agent struct {
		Uptime           time.Duration `json:"uptime"`
		DataQueueSize    int           `json:"data_queue_size"`
		LastBackendSync  time.Time     `json:"last_backend_sync"`
		BackendLatency   time.Duration `json:"backend_latency"`
		FailedRequests   int           `json:"failed_requests"`
		SuccessfulRequests int         `json:"successful_requests"`
	} `json:"agent"`

	// Security metrics
	Security struct {
		ThreatsDetected  int       `json:"threats_detected"`
		LastThreatTime   time.Time `json:"last_threat_time"`
		BlockedIPs       int       `json:"blocked_ips"`
		BlockedPorts     int       `json:"blocked_ports"`
		EncryptedData    int64     `json:"encrypted_data"`
	} `json:"security"`
}

// Collector handles metrics collection
type Collector struct {
	config     *config.Config
	metrics    *Metrics
	mu         sync.RWMutex
	startTime  time.Time
	stopChan   chan struct{}
	metricsChan chan<- *Metrics
}

// NewCollector creates a new metrics collector
func NewCollector(cfg *config.Config, metricsChan chan<- *Metrics) *Collector {
	return &Collector{
		config:     cfg,
		metrics:    &Metrics{},
		startTime:  time.Now(),
		stopChan:   make(chan struct{}),
		metricsChan: metricsChan,
	}
}

// Start begins metrics collection
func (c *Collector) Start(ctx context.Context) {
	ticker := time.NewTicker(c.config.Monitoring.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.collectMetrics()
		}
	}
}

// Stop stops metrics collection
func (c *Collector) Stop() {
	close(c.stopChan)
}

// collectMetrics collects all metrics
func (c *Collector) collectMetrics() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update timestamp and agent ID
	c.metrics.Timestamp = time.Now()
	c.metrics.AgentID = c.config.AgentID

	// Collect network metrics
	c.collectNetworkMetrics()

	// Collect system metrics
	c.collectSystemMetrics()

	// Collect agent metrics
	c.collectAgentMetrics()

	// Collect security metrics
	c.collectSecurityMetrics()

	// Send metrics to channel
	select {
	case c.metricsChan <- c.metrics:
	default:
		log.Printf("Warning: metrics channel is full, dropping metrics")
	}
}

// collectNetworkMetrics collects network-related metrics
func (c *Collector) collectNetworkMetrics() {
	// This would be implemented to collect actual network metrics
	// For now, we'll just update the structure
	c.metrics.Network.PacketsReceived++
	c.metrics.Network.BytesReceived += 1024 // Example
}

// collectSystemMetrics collects system-related metrics
func (c *Collector) collectSystemMetrics() {
	// This would be implemented to collect actual system metrics
	// For now, we'll just update the structure
	c.metrics.System.CPUUsage = 0.5 // Example
	c.metrics.System.MemoryUsage = 0.7 // Example
}

// collectAgentMetrics collects agent-related metrics
func (c *Collector) collectAgentMetrics() {
	c.metrics.Agent.Uptime = time.Since(c.startTime)
	c.metrics.Agent.DataQueueSize = 100 // Example
}

// collectSecurityMetrics collects security-related metrics
func (c *Collector) collectSecurityMetrics() {
	// This would be implemented to collect actual security metrics
	// For now, we'll just update the structure
	c.metrics.Security.ThreatsDetected++
}

// GetMetrics returns the current metrics
func (c *Collector) GetMetrics() *Metrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}

// UpdateNetworkStats updates network statistics
func (c *Collector) UpdateNetworkStats(received, dropped, filtered uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics.Network.PacketsReceived = received
	c.metrics.Network.PacketsDropped = dropped
	c.metrics.Network.PacketsFiltered = filtered
}

// UpdateBackendSync updates backend synchronization metrics
func (c *Collector) UpdateBackendSync(success bool, latency time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if success {
		c.metrics.Agent.SuccessfulRequests++
	} else {
		c.metrics.Agent.FailedRequests++
	}
	c.metrics.Agent.LastBackendSync = time.Now()
	c.metrics.Agent.BackendLatency = latency
}

// UpdateThreatMetrics updates threat detection metrics
func (c *Collector) UpdateThreatMetrics(threats int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics.Security.ThreatsDetected = threats
	c.metrics.Security.LastThreatTime = time.Now()
} 