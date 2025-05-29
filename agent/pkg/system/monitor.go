package system

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/osquery/osquery-go"
)

// MonitorConfig holds configuration for system monitoring
type MonitorConfig struct {
	SocketPath    string
	QueryInterval time.Duration
	EnableFIM     bool
	EnableUsers   bool
	EnableRegistry bool // Windows only
	ChannelSize   int
}

// DefaultConfig returns a default monitor configuration
func DefaultConfig(socketPath string) MonitorConfig {
	return MonitorConfig{
		SocketPath:    socketPath,
		QueryInterval: 10 * time.Second,
		EnableFIM:     true,
		EnableUsers:   true,
		EnableRegistry: runtime.GOOS == "windows",
		ChannelSize:   1000,
	}
}

// LogData represents normalized system log data
type LogData struct {
	Timestamp    time.Time         `json:"timestamp"`
	Source       string           `json:"source"`
	EventType    string           `json:"event_type"`
	Data         json.RawMessage  `json:"data"`
	Severity     string           `json:"severity,omitempty"`
	Host         string           `json:"host,omitempty"`
}

// Monitor represents a system monitoring session
type Monitor struct {
	client  *osquery.ExtensionManagerClient
	config  MonitorConfig
	stopped bool
	stats   MonitorStats
}

// MonitorStats holds monitoring statistics
type MonitorStats struct {
	EventsCollected uint64
	EventsDropped   uint64
	QueryErrors     uint64
}

// NewMonitor creates a new system monitoring session
func NewMonitor(config MonitorConfig) (*Monitor, error) {
	client, err := osquery.NewClient(config.SocketPath, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("error creating osquery client (is osqueryd running?): %v", err)
	}

	return &Monitor{
		client: client,
		config: config,
	}, nil
}

// Start begins collecting system logs and sends them to the provided channel
func (m *Monitor) Start(logs chan<- LogData, ctx context.Context) error {
	// Define base queries for system monitoring
	queries := map[string]string{
		"process_events": "SELECT * FROM process_events WHERE time > (SELECT unix_time FROM time) - 10;",
		"socket_events": "SELECT * FROM socket_events WHERE time > (SELECT unix_time FROM time) - 10;",
		"syslog":       "SELECT * FROM system_logs WHERE time > (SELECT unix_time FROM time) - 10;",
	}

	// Add FIM queries if enabled
	if m.config.EnableFIM {
		queries["file_events"] = "SELECT * FROM file_events WHERE time > (SELECT unix_time FROM time) - 10;"
		queries["fim_baseline"] = `
			SELECT f.path, f.directory, f.filename, f.symlink, f.size, h.sha256 
			FROM file f JOIN hash h ON f.path = h.path 
			WHERE f.path LIKE '/etc/%' OR f.path LIKE '/usr/bin/%' OR f.path LIKE '/usr/sbin/%';
		`
	}

	// Add user monitoring if enabled
	if m.config.EnableUsers {
		queries["user_events"] = "SELECT * FROM user_events WHERE time > (SELECT unix_time FROM time) - 10;"
		queries["logged_in_users"] = "SELECT * FROM logged_in_users;"
	}

	// Add Windows-specific queries
	if runtime.GOOS == "windows" && m.config.EnableRegistry {
		queries["registry_events"] = "SELECT * FROM windows_events WHERE eventid IN (12, 13, 14) AND time > (SELECT unix_time FROM time) - 10;"
		queries["windows_events"] = "SELECT * FROM windows_events WHERE source = 'Microsoft-Windows-Security-Auditing' AND time > (SELECT unix_time FROM time) - 10;"
	}

	go func() {
		ticker := time.NewTicker(m.config.QueryInterval)
		defer ticker.Stop()

		// Get hostname once at startup to avoid repeated queries
		sysInfo, err := m.GetSystemInfo()
		hostname := "unknown"
		if err == nil {
			hostname = sysInfo["hostname"]
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if m.stopped {
					return
				}

				for eventType, query := range queries {
					resp, err := m.client.Query(query)
					if err != nil {
						log.Printf("Error querying %s: %v", eventType, err)
						m.stats.QueryErrors++
						continue
					}

					for _, row := range resp.Response {
						m.stats.EventsCollected++

						// Convert row data to JSON
						jsonData, err := json.Marshal(row)
						if err != nil {
							log.Printf("Error marshaling %s data: %v", eventType, err)
							continue
						}

						logData := LogData{
							Timestamp: time.Now(),
							Source:    "osquery",
							EventType: eventType,
							Data:     jsonData,
							Host:     hostname,
						}

						// Set severity based on event type
						logData.Severity = getSeverity(eventType, row)

						select {
						case logs <- logData:
						default:
							m.stats.EventsDropped++
							log.Printf("Warning: log channel full, dropping %s event", eventType)
						}
					}
				}
			}
		}
	}()

	return nil
}

// Stop stops the system monitoring
func (m *Monitor) Stop() {
	m.stopped = true
	if m.client != nil {
		m.client.Close()
	}
}

// GetStats returns current monitoring statistics
func (m *Monitor) GetStats() MonitorStats {
	return m.stats
}

// GetSystemInfo retrieves basic system information
func (m *Monitor) GetSystemInfo() (map[string]string, error) {
	resp, err := m.client.Query("SELECT hostname, os_version, platform, cpu_brand, physical_memory FROM system_info;")
	if err != nil {
		return nil, fmt.Errorf("error querying system info: %v", err)
	}

	if len(resp.Response) == 0 {
		return nil, fmt.Errorf("no system info found")
	}

	return resp.Response[0], nil
}

// getSeverity determines event severity based on type and content
func getSeverity(eventType string, data map[string]string) string {
	switch eventType {
	case "process_events":
		// Elevated severity for processes running as root/SYSTEM
		if data["uid"] == "0" || data["username"] == "SYSTEM" {
			return "high"
		}
	case "file_events":
		// Higher severity for changes to system files
		path := data["path"]
		if path == "/etc/passwd" || path == "/etc/shadow" || path == "/etc/sudoers" {
			return "critical"
		}
	case "registry_events":
		// Higher severity for sensitive registry changes
		if data["path"] == "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services" {
			return "high"
		}
	}
	return "info"
}