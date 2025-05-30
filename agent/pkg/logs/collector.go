package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/smartshieldai-idps/agent/config"
)

// LogEntry represents a parsed log entry
type LogEntry struct {
	Timestamp time.Time       `json:"timestamp"`
	Source    string         `json:"source"`
	Type      string         `json:"type"`
	Data      json.RawMessage `json:"data"`
	Severity  string         `json:"severity"`
	Host      string         `json:"host"`
}

// Collector represents an application log collector
type Collector struct {
	config       *config.SystemConfig
	logsChan     chan<- []byte
	hostname     string
	watchers     map[string]*LogWatcher
	ReadFromStart bool // If true, read from start of file
}

// LogWatcher represents a log file watcher
type LogWatcher struct {
	Path     string
	Type     string
	LastPos  int64
	File     *os.File
	StopChan chan struct{}
}

// NewCollector creates a new application log collector
func NewCollector(cfg *config.SystemConfig, logsChan chan<- []byte, opts ...func(*Collector)) (*Collector, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	collector := &Collector{
		config:   cfg,
		logsChan: logsChan,
		hostname: hostname,
		watchers: make(map[string]*LogWatcher),
	}
	for _, opt := range opts {
		opt(collector)
	}
	return collector, nil
}

// Start begins log collection
func (c *Collector) Start(ctx context.Context) error {
	// Initialize log watchers for each supported application
	if err := c.initializeWatchers(); err != nil {
		return fmt.Errorf("failed to initialize log watchers: %v", err)
	}

	// Start watching logs
	for _, watcher := range c.watchers {
		go c.watchLog(ctx, watcher)
	}

	return nil
}

// Stop stops log collection
func (c *Collector) Stop() {
	for _, watcher := range c.watchers {
		close(watcher.StopChan)
		if watcher.File != nil {
			watcher.File.Close()
		}
	}
}

// initializeWatchers sets up watchers for supported application logs
func (c *Collector) initializeWatchers() error {
	var apacheLogs, nginxLogs, mysqlLogs []string
	switch runtime.GOOS {
	case "windows":
		apacheLogs = c.config.ApplicationLogs.Windows.Apache
		nginxLogs = c.config.ApplicationLogs.Windows.Nginx
		mysqlLogs = c.config.ApplicationLogs.Windows.MySQL
	case "darwin":
		apacheLogs = c.config.ApplicationLogs.Darwin.Apache
		nginxLogs = c.config.ApplicationLogs.Darwin.Nginx
		mysqlLogs = c.config.ApplicationLogs.Darwin.MySQL
	default:
		apacheLogs = c.config.ApplicationLogs.Linux.Apache
		nginxLogs = c.config.ApplicationLogs.Linux.Nginx
		mysqlLogs = c.config.ApplicationLogs.Linux.MySQL
	}

	for _, path := range apacheLogs {
		if err := c.addWatcher(path, "apache"); err != nil {
			log.Printf("Warning: Failed to add Apache log watcher for %s: %v", path, err)
		}
	}
	for _, path := range nginxLogs {
		if err := c.addWatcher(path, "nginx"); err != nil {
			log.Printf("Warning: Failed to add Nginx log watcher for %s: %v", path, err)
		}
	}
	for _, path := range mysqlLogs {
		if err := c.addWatcher(path, "mysql"); err != nil {
			log.Printf("Warning: Failed to add MySQL log watcher for %s: %v", path, err)
		}
	}
	return nil
}

// addWatcher adds a new log file watcher
func (c *Collector) addWatcher(path, logType string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("log file does not exist: %v", err)
	}
	watcher := &LogWatcher{
		Path:     path,
		Type:     logType,
		StopChan: make(chan struct{}),
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open log file: %v", err)
	}
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("failed to stat log file: %v", err)
	}
	watcher.File = file
	if c.ReadFromStart {
		watcher.LastPos = 0
	} else {
		watcher.LastPos = stat.Size()
	}
	c.watchers[path] = watcher
	return nil
}

// watchLog watches a log file for changes
func (c *Collector) watchLog(ctx context.Context, watcher *LogWatcher) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-watcher.StopChan:
			return
		case <-ticker.C:
			if err := c.processLogFile(watcher); err != nil {
				log.Printf("Error processing log file %s: %v", watcher.Path, err)
			}
		}
	}
}

// processLogFile processes new entries in a log file
func (c *Collector) processLogFile(watcher *LogWatcher) error {
	// Get current file size
	stat, err := watcher.File.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %v", err)
	}

	// If file size is less than last position, file was truncated
	if stat.Size() < watcher.LastPos {
		log.Printf("DEBUG: File %s was truncated, resetting position from %d to 0", watcher.Path, watcher.LastPos)
		watcher.LastPos = 0
	}

	// If no new data, return
	if stat.Size() == watcher.LastPos {
		return nil
	}

	// Read new data
	buf := make([]byte, stat.Size()-watcher.LastPos)
	_, err = watcher.File.ReadAt(buf, watcher.LastPos)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	// Update last position
	watcher.LastPos = stat.Size()

	// Process new entries
	entries := strings.Split(string(buf), "\n")
	log.Printf("DEBUG: Processing %d entries from %s", len(entries), watcher.Path)
	for _, entry := range entries {
		if entry == "" {
			continue
		}

		log.Printf("DEBUG: Processing entry from %s: %q", watcher.Path, entry)

		// Parse log entry based on type
		var logEntry LogEntry
		var err error

		switch watcher.Type {
		case "apache":
			logEntry, err = c.parseApacheLog(entry)
		case "nginx":
			logEntry, err = c.parseNginxLog(entry)
		case "mysql":
			logEntry, err = c.parseMySQLLog(entry)
		default:
			continue
		}

		if err != nil {
			log.Printf("Warning: Failed to parse log entry: %v", err)
			continue
		}

		// Set common fields
		logEntry.Source = watcher.Type
		logEntry.Type = watcher.Type
		logEntry.Host = c.hostname

		// Marshal and send
		data, err := json.Marshal(logEntry)
		if err != nil {
			log.Printf("Warning: Failed to marshal log entry: %v", err)
			continue
		}

		log.Printf("DEBUG: Sending log entry: type=%s, severity=%s", logEntry.Type, logEntry.Severity)

		select {
		case c.logsChan <- data:
		default:
			log.Printf("Warning: Log channel is full, dropping entry")
		}
	}

	return nil
}

// parseApacheLog parses an Apache log entry
func (c *Collector) parseApacheLog(entry string) (LogEntry, error) {
	if strings.Contains(entry, "[error]") {
		parts := strings.SplitN(entry, "]", 3)
		if len(parts) < 3 {
			log.Printf("DEBUG: Apache error log entry: %q", entry)
			return LogEntry{}, fmt.Errorf("invalid Apache error log format")
		}
		timestampStr := strings.Trim(parts[0], "[]")
		timestamp, err := time.Parse("Mon Jan 02 15:04:05 2006", timestampStr)
		if err != nil {
			log.Printf("DEBUG: Apache error log timestamp parse error: %q, value: %q", err, timestampStr)
			return LogEntry{}, fmt.Errorf("invalid timestamp: %v", err)
		}
		data, _ := json.Marshal(entry)
		return LogEntry{
			Timestamp: timestamp,
			Data:      data,
			Type:      "apache",
			Severity:  "error",
		}, nil
	}
	parts := strings.Split(entry, " ")
	if len(parts) < 7 {
		log.Printf("DEBUG: Apache access log entry: %q", entry)
		return LogEntry{}, fmt.Errorf("invalid Apache log format")
	}
	log.Printf("DEBUG: Apache access log parts[3]=%q, parts[4]=%q", parts[3], parts[4])
	timestampStr := strings.Trim((parts[3] + " " + parts[4]), "[]")
	log.Printf("DEBUG: Apache access log timestampStr=%q", timestampStr)
	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", timestampStr)
	if err != nil {
		log.Printf("DEBUG: Apache access log timestamp parse error: %q, value: %q", err, timestampStr)
		return LogEntry{}, fmt.Errorf("invalid timestamp: %v", err)
	}
	severity := "info"
	if len(parts) > 8 {
		statusCode := parts[8]
		if statusCode >= "400" {
			severity = "error"
		} else if statusCode >= "300" {
			severity = "warning"
		}
	}
	data, _ := json.Marshal(entry)
	return LogEntry{
		Timestamp: timestamp,
		Data:      data,
		Severity:  severity,
	}, nil
}

// parseNginxLog parses an Nginx log entry
func (c *Collector) parseNginxLog(entry string) (LogEntry, error) {
	parts := strings.Split(entry, " ")
	if len(parts) < 7 {
		log.Printf("DEBUG: Nginx access log entry: %q", entry)
		return LogEntry{}, fmt.Errorf("invalid Nginx log format")
	}
	log.Printf("DEBUG: Nginx access log parts[3]=%q, parts[4]=%q", parts[3], parts[4])
	timestampStr := strings.Trim((parts[3] + " " + parts[4]), "[]")
	log.Printf("DEBUG: Nginx access log timestampStr=%q", timestampStr)
	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", timestampStr)
	if err != nil {
		log.Printf("DEBUG: Nginx access log timestamp parse error: %q, value: %q", err, timestampStr)
		return LogEntry{}, fmt.Errorf("invalid timestamp: %v", err)
	}
	severity := "info"
	if len(parts) > 8 {
		statusCode := parts[8]
		if statusCode >= "400" {
			severity = "error"
		} else if statusCode >= "300" {
			severity = "warning"
		}
	}
	data, _ := json.Marshal(entry)
	return LogEntry{
		Timestamp: timestamp,
		Data:      data,
		Severity:  severity,
	}, nil
}

// parseMySQLLog parses a MySQL log entry
func (c *Collector) parseMySQLLog(entry string) (LogEntry, error) {
	parts := strings.SplitN(entry, " ", 3)
	if len(parts) < 3 {
		log.Printf("DEBUG: MySQL log entry: %q", entry)
		return LogEntry{}, fmt.Errorf("invalid MySQL log format")
	}
	timestampStr := parts[0] + " " + parts[1]
	timestamp, err := time.Parse("2006-01-02 15:04:05", timestampStr)
	if err != nil {
		log.Printf("DEBUG: MySQL log timestamp parse error: %q, value: %q", err, timestampStr)
		return LogEntry{}, fmt.Errorf("invalid timestamp: %v", err)
	}
	severity := "info"
	lowerEntry := strings.ToLower(entry)
	if strings.Contains(lowerEntry, "error") {
		severity = "error"
	} else if strings.Contains(lowerEntry, "warning") {
		severity = "warning"
	}
	data, _ := json.Marshal(entry)
	return LogEntry{
		Timestamp: timestamp,
		Data:      data,
		Severity:  severity,
	}, nil
} 