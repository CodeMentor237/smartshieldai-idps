package system

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/smartshieldai-idps/agent/config"
	"github.com/smartshieldai-idps/agent/pkg/system/fim"
)

// Default paths to monitor per platform
var defaultMonitorPaths = map[string][]string{
	"windows": {
		"C:\\Windows\\System32",
		"C:\\Program Files",
		"C:\\Program Files (x86)",
		"C:\\Users",
	},
	"linux": {
		"/etc",
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/var/log",
	},
	"darwin": {
		"/etc",
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/var/log",
		"/Applications",
	},
}

// Default paths to exclude per platform
var defaultExcludePaths = map[string][]string{
	"windows": {
		"C:\\Windows\\System32\\LogFiles",
		"C:\\Windows\\System32\\config\\systemprofile",
	},
	"linux": {
		"/var/log/lastlog",
		"/var/log/wtmp",
		"/var/log/btmp",
	},
	"darwin": {
		"/var/log/asl",
		"/var/log/install.log",
	},
}

// MonitorConfig holds system monitoring configuration
type MonitorConfig struct {
	FIMConfig     fim.Config
	QueryInterval time.Duration
}

// LogData represents system log data
type LogData struct {
	Timestamp time.Time       `json:"timestamp"`
	Source    string         `json:"source"`
	EventType string         `json:"event_type"`
	Data      json.RawMessage `json:"data"`
	Severity  string         `json:"severity"`
	Host      string         `json:"host"`
}

// Monitor represents a system monitoring session
type Monitor struct {
	config    *config.SystemConfig
	stats     *Stats
	logsChan  chan<- []byte
	hostname  string
}

// Stats represents monitoring statistics
type Stats struct {
	LogsProcessed uint64
	LastUpdate    time.Time
}

// DefaultConfig returns default configuration for the current platform
func DefaultConfig() MonitorConfig {
	platform := runtime.GOOS

	paths := defaultMonitorPaths[platform]
	if paths == nil {
		paths = defaultMonitorPaths["linux"] // fallback to linux paths
	}

	return MonitorConfig{
		QueryInterval: 30 * time.Second,
		FIMConfig: fim.Config{
			Paths:          paths,
			ExcludePaths:   defaultExcludePaths[platform],
			HashAlgorithm:  "sha256",
			ScanInterval:   5 * time.Minute,
			EnableRealtime: true,
		},
	}
}

// NewMonitor creates a new system monitor
func NewMonitor(cfg *config.SystemConfig) (*Monitor, error) {
	// Verify log paths exist
	for _, path := range cfg.LogPaths {
		// Expand environment variables in path
		expandedPath := os.ExpandEnv(path)
		
		// Check if path exists
		if _, err := os.Stat(expandedPath); err != nil {
			if os.IsNotExist(err) {
				// Skip non-existent paths instead of failing
				continue
			}
			return nil, fmt.Errorf("error checking log path %s: %v", expandedPath, err)
		}
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return &Monitor{
		config:   cfg,
		stats: &Stats{
			LastUpdate: time.Now(),
		},
		hostname: hostname,
	}, nil
}

// Start begins system monitoring
func (m *Monitor) Start(ctx context.Context, logChan chan<- []byte) error {
	log.Printf("Starting system monitoring for paths: %v", m.config.LogPaths)
	m.logsChan = logChan

	// Start the query loop
	go m.queryLoop(ctx)

	return nil
}

// Stop stops system monitoring
func (m *Monitor) Stop() {
	log.Printf("Stopping system monitoring")
}

// GetStats returns monitoring statistics
func (m *Monitor) GetStats() *Stats {
	return m.stats
}

// CollectSystemInfo collects system information
func (m *Monitor) CollectSystemInfo() (map[string]interface{}, error) {
	// This is a placeholder for actual system info collection
	// In a real implementation, this would collect actual system metrics
	return map[string]interface{}{
		"hostname":    "localhost",
		"os":         "linux",
		"kernel":     "5.4.0",
		"cpu_cores":  4,
		"memory_gb":  8,
		"disk_gb":    100,
		"uptime_sec": 3600,
	}, nil
}

// queryLoop performs periodic system queries
func (m *Monitor) queryLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // Use fixed interval for now
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Collect process information
			if procs, err := m.collectProcessInfo(); err == nil {
				data, _ := json.Marshal(procs)
				m.logsChan <- []byte(fmt.Sprintf(`{"timestamp":"%s","source":"system","event_type":"processes","data":%s,"host":"%s"}`, 
					time.Now().Format(time.RFC3339), data, m.hostname))
			}

			// Collect network connections
			if conns, err := m.collectNetworkConnections(); err == nil {
				data, _ := json.Marshal(conns)
				m.logsChan <- []byte(fmt.Sprintf(`{"timestamp":"%s","source":"system","event_type":"connections","data":%s,"host":"%s"}`, 
					time.Now().Format(time.RFC3339), data, m.hostname))
			}

			// Collect system info
			if sysInfo, err := m.CollectSystemInfo(); err == nil {
				data, _ := json.Marshal(sysInfo)
				m.logsChan <- []byte(fmt.Sprintf(`{"timestamp":"%s","source":"system","event_type":"system_info","data":%s,"host":"%s"}`, 
					time.Now().Format(time.RFC3339), data, m.hostname))
			}
		}
	}
}

// collectProcessInfo gathers information about running processes
func (m *Monitor) collectProcessInfo() ([]map[string]interface{}, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var processInfo []map[string]interface{}
	for _, p := range processes {
		info := make(map[string]interface{})
		
		if name, err := p.Name(); err == nil {
			info["name"] = name
		}
		if exe, err := p.Exe(); err == nil {
			info["exe"] = exe
		}
		if cmdline, err := p.Cmdline(); err == nil {
			info["cmdline"] = cmdline
		}
		if createTime, err := p.CreateTime(); err == nil {
			info["create_time"] = createTime
		}
		if cpu, err := p.CPUPercent(); err == nil {
			info["cpu_percent"] = cpu
		}
		if mem, err := p.MemoryInfo(); err == nil {
			info["memory"] = mem
		}

		processInfo = append(processInfo, info)
	}

	return processInfo, nil
}

// collectNetworkConnections gathers information about network connections
func (m *Monitor) collectNetworkConnections() ([]net.ConnectionStat, error) {
	return net.Connections("all")
}

// processFIMEvents handles file integrity monitoring events
func (m *Monitor) processFIMEvents(events chan fim.Event, ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			data, err := json.Marshal(event)
			if err != nil {
				log.Printf("Error marshaling FIM event: %v", err)
				continue
			}

			severity := "info"
			if event.Type == "Modified" || event.Type == "PermissionChanged" {
				severity = "warning"
			} else if event.Type == "Deleted" {
				severity = "critical"
			}

			m.logsChan <- []byte(fmt.Sprintf(`{"timestamp":"%s","source":"fim","event_type":"%s","data":%s,"severity":"%s","host":"%s"}`, 
				event.Timestamp.Format(time.RFC3339), event.Type, data, severity, m.hostname))
		}
	}
}