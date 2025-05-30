package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
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
	"github.com/smartshieldai-idps/agent/pkg/endpoint"
	"github.com/smartshieldai-idps/agent/pkg/monitoring"
	"github.com/smartshieldai-idps/agent/pkg/network"
	"github.com/smartshieldai-idps/agent/pkg/security"
	"github.com/smartshieldai-idps/agent/pkg/system"
)

// Global configuration
const (
	maxPacketQueueSize = 10000
	maxLogQueueSize    = 10000
	maxOsqueryQueueSize = 1000
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
	// Define and parse command-line flags
	configFile := flag.String("config", "", "Path to the agent configuration file. If not provided, tries default locations.")
	flag.Parse()

	// Load configuration
	var cfg *config.Config
	var err error

	if *configFile != "" {
		log.Printf("Loading configuration from specified file: %s", *configFile)
		cfg, err = config.LoadConfig(*configFile)
	} else {
		// Try default locations if no config file is specified
		// 1. Next to the executable
		exePath, exeErr := os.Executable()
		if exeErr == nil {
			defaultPath := filepath.Join(filepath.Dir(exePath), "config.yaml")
			log.Printf("Attempting to load configuration from default location: %s", defaultPath)
			cfg, err = config.LoadConfig(defaultPath)
			if err == nil {
				log.Printf("Successfully loaded configuration from %s", defaultPath)
			}
		}

		// 2. If not found next to executable, or error getting exe path, use built-in defaults
		if cfg == nil || err != nil {
			if err != nil {
				log.Printf("Failed to load from default executable location (%v), falling back to built-in defaults.", err)
			} else {
				log.Println("Configuration file not found in default locations, falling back to built-in defaults.")
			}
			cfg = config.DefaultConfig()
			err = nil // Reset error as we are using defaults
		}
	}

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
				MinVersion: tls.VersionTLS13,
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
	log.Println("Initializing network capture...")
	networkCapture, err := network.NewCapture(&cfg.Network)
	if err != nil {
		log.Fatalf("Failed to initialize network capture: %v", err)
	}
	packetChan := make(chan []byte, 1000)
	
	// Start network capture in a goroutine with error handling
	errChan := make(chan error, 1)
	go func() {
		if err := networkCapture.Start(ctx, packetChan); err != nil {
			log.Printf("Network capture failed to start: %v", err)
			errChan <- err
		}
	}()

	// Wait briefly to check if network capture started successfully
	select {
	case err := <-errChan:
		log.Fatalf("Network capture failed to start: %v", err)
	case <-time.After(2 * time.Second):
		log.Println("Network capture started successfully")
	}

	// Initialize system monitor
	systemMonitor, err := system.NewMonitor(&cfg.System)
	if err != nil {
		log.Fatalf("Failed to initialize system monitor: %v", err)
	}
	logChan := make(chan []byte, 1000)
	go systemMonitor.Start(ctx, logChan)

	// Initialize Osquery client and start scheduler
	osquerySocketPath := cfg.System.OsquerySocketPath
	if osquerySocketPath == "" {
		osquerySocketPath = getOsquerySocket()
		log.Printf("OsquerySocketPath not configured, using auto-detected path: %s", osquerySocketPath)
	}

	osqueryClient, err := endpoint.NewOsqueryClient(osquerySocketPath)
	if err != nil {
		log.Printf("Failed to initialize Osquery client (socket: %s): %v. Osquery monitoring will be disabled.", osquerySocketPath, err)
		// We don't make this fatal, agent can run without osquery
	}
	
	osqueryChan := make(chan []byte, maxOsqueryQueueSize)
	if osqueryClient != nil {
		log.Println("Initializing Osquery data collection...")
		go osqueryClient.ScheduleQueries(ctx, osqueryChan)
	}

	// Start data processing
	go processData(ctx, cfg, httpClient, rateLimiter, encryptor, packetChan, logChan, osqueryChan, metricsCollector, healthChecker)

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
	if osqueryClient != nil {
		close(osqueryChan)
	}

	// Wait for all goroutines to finish
	wg.Wait()
	log.Println("Agent shutdown complete")
}

func processData(ctx context.Context, cfg *config.Config, client *http.Client, rateLimiter *security.RateLimiter, encryptor *security.Encryptor, packetChan, logChan, osqueryChan <-chan []byte, metrics *monitoring.Collector, health *monitoring.HealthChecker) {
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-packetChan:
			processPacket(ctx, cfg, client, rateLimiter, encryptor, packet, metrics, health)
		case logData := <-logChan:
			processLog(ctx, cfg, client, rateLimiter, encryptor, logData, metrics, health)
		case osqueryData := <-osqueryChan:
			if osqueryData != nil {
				processOsqueryData(ctx, cfg, client, rateLimiter, encryptor, osqueryData, metrics, health)
			}
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

func processLog(ctx context.Context, cfg *config.Config, client *http.Client, rateLimiter *security.RateLimiter, encryptor *security.Encryptor, logData []byte, metrics *monitoring.Collector, health *monitoring.HealthChecker) {
	// Check rate limit
	if !rateLimiter.Allow() {
		health.ReportError(fmt.Errorf("rate limit exceeded for log processing"))
		return
	}

	// Encrypt log data if enabled
	var data []byte
	var err error
	if cfg.Security.EnablePayloadEncryption {
		data, err = encryptor.Encrypt(logData)
		if err != nil {
			health.ReportError(fmt.Errorf("failed to encrypt log: %v", err))
			return
		}
	} else {
		data = logData
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

func processOsqueryData(ctx context.Context, cfg *config.Config, client *http.Client, rateLimiter *security.RateLimiter, encryptor *security.Encryptor, osqueryData []byte, metrics *monitoring.Collector, health *monitoring.HealthChecker) {
	// Check rate limit
	if !rateLimiter.Allow() {
		health.ReportError(fmt.Errorf("rate limit exceeded for osquery data processing"))
		return
	}

	// Encrypt osquery data if enabled
	var data []byte
	var err error
	if cfg.Security.EnablePayloadEncryption {
		data, err = encryptor.Encrypt(osqueryData)
		if err != nil {
			health.ReportError(fmt.Errorf("failed to encrypt osquery data: %v", err))
			return
		}
	} else {
		data = osqueryData
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
		health.ReportError(fmt.Errorf("failed to send osquery data to backend: %v", err))
		metrics.UpdateBackendSync(false, time.Since(start))
		return
	}

	// Update metrics
	metrics.UpdateBackendSync(true, time.Since(start))
	log.Printf("Successfully sent osquery data to backend.")
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