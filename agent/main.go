package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/smartshieldai-idps/agent/config"
	"github.com/smartshieldai-idps/agent/pkg/monitoring"
	"github.com/smartshieldai-idps/agent/pkg/network"
	"github.com/smartshieldai-idps/agent/pkg/security"
	"github.com/smartshieldai-idps/agent/pkg/system"
)

// Global configuration
const (
	maxPacketQueueSize = 10000
	maxLogQueueSize    = 10000
	statInterval       = 30 * time.Second
	backendURL         = "https://localhost:8080/api/v1/data"
	agentID            = "agent-001"
)

// DataIngestionRequest represents the data sent to the backend
type DataIngestionRequest struct {
	AgentID   string          `json:"agent_id"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	log.Println("Starting SmartShield AI IDPS Agent...")

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize HTTP client with TLS
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.TLS.InsecureSkipVerify,
			},
		},
		Timeout: cfg.Backend.Timeout,
	}

	// Initialize rate limiter
	rateLimiter := security.NewRateLimiter(cfg.Security.RateLimit, cfg.Security.RateLimitBurst)

	// Initialize encryptor
	encryptor, err := security.NewEncryptor([]byte(cfg.Security.EncryptionKey))
	if err != nil {
		log.Fatalf("Failed to initialize encryptor: %v", err)
	}

	// Initialize metrics collector
	metricsChan := make(chan *monitoring.Metrics, 100)
	metricsCollector := monitoring.NewCollector(cfg, metricsChan)
	go metricsCollector.Start(ctx)

	// Initialize health checker
	healthChecker := monitoring.NewHealthChecker(cfg, metricsCollector)
	go healthChecker.Start(ctx)

	// Initialize network capture
	networkCapture, err := network.NewCapture(&cfg.Network)
	if err != nil {
		log.Fatalf("Failed to initialize network capture: %v", err)
	}
	packetChan := make(chan []byte, 1000)
	go networkCapture.Start(ctx, packetChan)

	// Initialize system monitor
	systemMonitor, err := system.NewMonitor(&cfg.System)
	if err != nil {
		log.Fatalf("Failed to initialize system monitor: %v", err)
	}
	logChan := make(chan []byte, 1000)
	go systemMonitor.Start(ctx, logChan)

	// Start data processing
	go processData(ctx, cfg, httpClient, rateLimiter, encryptor, packetChan, logChan, metricsCollector, healthChecker)

	// Start statistics reporting
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(statInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Report network statistics
				stats := networkCapture.GetStats()
				log.Printf("Network stats: Received=%d, Dropped=%d, Filtered=%d",
					stats.PacketsReceived, stats.PacketsDropped, stats.PacketsFiltered)

				// Report system monitoring statistics
				if systemMonitor != nil {
					log.Printf("System monitoring is active")
				}
			}
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	// Graceful shutdown
	log.Println("Shutting down...")
	cancel()
	time.Sleep(time.Second) // Give time for goroutines to clean up

	// Close channels after all producers are stopped
	close(packetChan)
	close(logChan)

	// Wait for all goroutines to finish
	wg.Wait()
	log.Println("Agent shutdown complete")
}

func processData(ctx context.Context, cfg *config.Config, client *http.Client, rateLimiter *security.RateLimiter, encryptor *security.Encryptor, packetChan, logChan <-chan []byte, metrics *monitoring.Collector, health *monitoring.HealthChecker) {
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-packetChan:
			processPacket(ctx, cfg, client, rateLimiter, encryptor, packet, metrics, health)
		case log := <-logChan:
			processLog(ctx, cfg, client, rateLimiter, encryptor, log, metrics, health)
		}
	}
}

func processPacket(ctx context.Context, cfg *config.Config, client *http.Client, rateLimiter *security.RateLimiter, encryptor *security.Encryptor, packet []byte, metrics *monitoring.Collector, health *monitoring.HealthChecker) {
	// Check rate limit
	if !rateLimiter.Allow() {
		health.ReportError(fmt.Errorf("rate limit exceeded for packet processing"))
		return
	}

	// Encrypt packet data if enabled
	var data []byte
	var err error
	if cfg.Security.EnablePayloadEncryption {
		data, err = encryptor.Encrypt(packet)
		if err != nil {
			health.ReportError(fmt.Errorf("failed to encrypt packet: %v", err))
			return
		}
	} else {
		data = packet
	}

	// Create request
	req := DataIngestionRequest{
		AgentID:   cfg.AgentID,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Send to backend
	start := time.Now()
	if err := sendToBackend(ctx, client, req); err != nil {
		health.ReportError(fmt.Errorf("failed to send packet to backend: %v", err))
		metrics.UpdateBackendSync(false, time.Since(start))
		return
	}

	// Update metrics
	metrics.UpdateBackendSync(true, time.Since(start))
	metrics.UpdateNetworkStats(1, 0, 0)
}

func processLog(ctx context.Context, cfg *config.Config, client *http.Client, rateLimiter *security.RateLimiter, encryptor *security.Encryptor, log []byte, metrics *monitoring.Collector, health *monitoring.HealthChecker) {
	// Check rate limit
	if !rateLimiter.Allow() {
		health.ReportError(fmt.Errorf("rate limit exceeded for log processing"))
		return
	}

	// Encrypt log data if enabled
	var data []byte
	var err error
	if cfg.Security.EnablePayloadEncryption {
		data, err = encryptor.Encrypt(log)
		if err != nil {
			health.ReportError(fmt.Errorf("failed to encrypt log: %v", err))
			return
		}
	} else {
		data = log
	}

	// Create request
	req := DataIngestionRequest{
		AgentID:   cfg.AgentID,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Send to backend
	start := time.Now()
	if err := sendToBackend(ctx, client, req); err != nil {
		health.ReportError(fmt.Errorf("failed to send log to backend: %v", err))
		metrics.UpdateBackendSync(false, time.Since(start))
		return
	}

	// Update metrics
	metrics.UpdateBackendSync(true, time.Since(start))
}

func sendToBackend(ctx context.Context, client *http.Client, req DataIngestionRequest) error {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", backendURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// getOsquerySocket returns the appropriate osquery socket path for the current OS
func getOsquerySocket() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\osquery.em` // Windows named pipe
	}
	// Unix domain socket path
	return filepath.Join("/var/osquery", "osquery.em")
}