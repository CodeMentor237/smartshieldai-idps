package test

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/smartshieldai-idps/agent/config"
	"github.com/smartshieldai-idps/agent/pkg/logs"
)

// Add this option function for tests
func WithReadFromStart() func(*logs.Collector) {
	return func(c *logs.Collector) {
		c.ReadFromStart = true
	}
}

// TestLogCollector tests the application log collector
func TestLogCollector(t *testing.T) {
	// Create temporary directory for test logs
	tempDir, err := os.MkdirTemp("", "log_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test log files
	apacheLog := filepath.Join(tempDir, "apache_access.log")
	nginxLog := filepath.Join(tempDir, "nginx_access.log")
	mysqlLog := filepath.Join(tempDir, "mysql.log")

	// Write test data to log files
	testData := map[string]string{
		apacheLog: `127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "Mozilla/5.0"` + "\n",
		nginxLog:  `127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "Mozilla/5.0"` + "\n",
		mysqlLog:  `2023-10-10 13:55:36 0 [Note] Server started` + "\n",
	}

	for path, data := range testData {
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatalf("Failed to write test data to %s: %v", path, err)
		}
	}

	// Create test configuration
	cfg := &config.Config{
		System: config.SystemConfig{
			ApplicationLogs: config.ApplicationLogPaths{
				Linux: struct {
					Apache []string `json:"apache"`
					Nginx  []string `json:"nginx"`
					MySQL  []string `json:"mysql"`
				}{
					Apache: []string{apacheLog},
					Nginx:  []string{nginxLog},
					MySQL:  []string{mysqlLog},
				},
			},
		},
	}

	// Create channel for log entries
	logChan := make(chan []byte, 100)

	// Create and start collector
	collector, err := logs.NewCollector(&cfg.System, logChan, WithReadFromStart())
	if err != nil {
		t.Fatalf("Failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		t.Fatalf("Failed to start collector: %v", err)
	}

	// Wait for log entries
	var entries []logs.LogEntry
	timeout := time.After(2 * time.Second)

	for {
		select {
		case data := <-logChan:
			var entry logs.LogEntry
			if err := json.Unmarshal(data, &entry); err != nil {
				t.Errorf("Failed to unmarshal log entry: %v", err)
				continue
			}
			entries = append(entries, entry)
			if len(entries) == 3 {
				goto Done
			}
		case <-timeout:
			goto Done
		}
	}
Done:

	// Verify results
	if len(entries) != 3 {
		t.Errorf("Expected 3 log entries, got %d", len(entries))
	}

	// Check each entry
	for _, entry := range entries {
		switch entry.Type {
		case "apache":
			if entry.Severity != "info" {
				t.Errorf("Expected severity 'info' for Apache, got '%s'", entry.Severity)
			}
		case "nginx":
			if entry.Severity != "info" {
				t.Errorf("Expected severity 'info' for Nginx, got '%s'", entry.Severity)
			}
		case "mysql":
			if entry.Severity != "info" {
				t.Errorf("Expected severity 'info' for MySQL, got '%s'", entry.Severity)
			}
		default:
			t.Errorf("Unexpected log type: %s", entry.Type)
		}
	}

	// Test error log
	errorLog := filepath.Join(tempDir, "apache_error.log")
	errorData := `[Wed Oct 10 13:55:36 2023] [error] [client 127.0.0.1] File not found: /var/www/html/missing.html` + "\n"
	if err := os.WriteFile(errorLog, []byte(errorData), 0644); err != nil {
		t.Fatalf("Failed to write error log: %v", err)
	}

	// Stop the current collector
	collector.Stop()

	// Drain the channel to remove any old entries
	for {
		select {
		case <-logChan:
			// discard
		default:
			break
		}
	}

	// Create a fresh config for the error log
	errorCfg := &config.Config{
		System: config.SystemConfig{
			ApplicationLogs: config.ApplicationLogPaths{
				Linux: struct {
					Apache []string `json:"apache"`
					Nginx  []string `json:"nginx"`
					MySQL  []string `json:"mysql"`
				}{
					Apache: []string{errorLog},
				},
			},
		},
	}

	// Create a new collector for the error log
	errorCollector, err := logs.NewCollector(&errorCfg.System, logChan, WithReadFromStart())
	if err != nil {
		t.Fatalf("Failed to create collector for error log: %v", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := errorCollector.Start(ctx); err != nil {
		t.Fatalf("Failed to start collector for error log: %v", err)
	}

	// Wait for error log entry
	timeout = time.After(5 * time.Second)
	var errorEntry logs.LogEntry
Found:
	for {
		select {
		case data := <-logChan:
			var entry logs.LogEntry
			if err := json.Unmarshal(data, &entry); err != nil {
				t.Errorf("Failed to unmarshal error log entry: %v", err)
				continue
			}
			log.Printf("DEBUG: Received log entry: type=%s, severity=%s", entry.Type, entry.Severity)
			log.Printf("DEBUG: Full entry: %+v", entry)
			log.Printf("DEBUG: Waiting for error log entry...")
			if entry.Type == "apache" && entry.Severity == "error" {
				errorEntry = entry
				goto Found
			}
		case <-timeout:
			t.Error("Timeout waiting for error log entry")
			goto Found
		}
	}
	// Verify error log entry
	if errorEntry.Type != "apache" {
		t.Errorf("Expected type 'apache' for error log, got '%s'", errorEntry.Type)
	}
	if errorEntry.Severity != "error" {
		t.Errorf("Expected severity 'error' for error log, got '%s'", errorEntry.Severity)
	}
}

// TestLogRotation tests log file rotation handling
func TestLogRotation(t *testing.T) {
	// Create temporary directory for test logs
	tempDir, err := os.MkdirTemp("", "log_rotation_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test log file
	logPath := filepath.Join(tempDir, "test.log")
	initialData := `127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "Mozilla/5.0"` + "\n"
	if err := os.WriteFile(logPath, []byte(initialData), 0644); err != nil {
		t.Fatalf("Failed to write initial log data: %v", err)
	}

	// Create test configuration
	cfg := &config.Config{
		System: config.SystemConfig{
			ApplicationLogs: config.ApplicationLogPaths{
				Linux: struct {
					Apache []string `json:"apache"`
					Nginx  []string `json:"nginx"`
					MySQL  []string `json:"mysql"`
				}{
					Apache: []string{logPath},
				},
			},
		},
	}

	// Create channel for log entries
	logChan := make(chan []byte, 100)

	// Create and start collector
	collector, err := logs.NewCollector(&cfg.System, logChan, WithReadFromStart())
	if err != nil {
		t.Fatalf("Failed to create collector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		t.Fatalf("Failed to start collector: %v", err)
	}

	// Wait for initial entry
	timeout := time.After(2 * time.Second)
	var initialEntry logs.LogEntry
	select {
	case data := <-logChan:
		if err := json.Unmarshal(data, &initialEntry); err != nil {
			t.Errorf("Failed to unmarshal initial log entry: %v", err)
		}
		if initialEntry.Type != "apache" {
			t.Errorf("Expected type 'apache' for initial log, got '%s'", initialEntry.Type)
		}
	case <-timeout:
		t.Error("Timeout waiting for initial log entry")
	}

	// Stop the collector before truncating
	collector.Stop()

	// Simulate log rotation by truncating the file
	if err := os.Truncate(logPath, 0); err != nil {
		t.Fatalf("Failed to truncate log file: %v", err)
	}

	// Write new data
	newData := `127.0.0.1 - - [10/Oct/2023:13:55:37 -0700] "GET /test HTTP/1.1" 404 2326 "-" "Mozilla/5.0"` + "\n"
	if err := os.WriteFile(logPath, []byte(newData), 0644); err != nil {
		t.Fatalf("Failed to write new log data: %v", err)
	}

	// Create new collector for the rotated log
	collector, err = logs.NewCollector(&cfg.System, logChan, WithReadFromStart())
	if err != nil {
		t.Fatalf("Failed to create collector for rotated log: %v", err)
	}

	if err := collector.Start(ctx); err != nil {
		t.Fatalf("Failed to start collector for rotated log: %v", err)
	}

	// Wait for new entry
	timeout = time.After(2 * time.Second)
	select {
	case data := <-logChan:
		var entry logs.LogEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			t.Errorf("Failed to unmarshal new log entry: %v", err)
		}
		if entry.Type != "apache" {
			t.Errorf("Expected type 'apache' for new log, got '%s'", entry.Type)
		}
		if entry.Severity != "error" {
			t.Errorf("Expected severity 'error' for 404 status, got '%s'", entry.Severity)
		}
	case <-timeout:
		t.Error("Timeout waiting for log entry after rotation")
	}
} 