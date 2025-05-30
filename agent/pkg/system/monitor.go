package system

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
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

// Metrics represents system monitoring metrics
type Metrics struct {
	LogEventsProcessed    int64
	ServiceChecksPerformed int64
	FileSystemEvents      int64
	LastUpdate            time.Time
}

// NewMetrics creates a new Metrics instance
func NewMetrics() *Metrics {
	return &Metrics{
		LastUpdate: time.Now(),
	}
}

// LogEvent represents a log file event
type LogEvent struct {
	Timestamp time.Time
	Source    string
	Path      string
	Content   string
}

// ServiceEvent represents a service status event
type ServiceEvent struct {
	Timestamp time.Time
	Name      string
	Status    string
}

// Monitor represents a system monitor
type Monitor struct {
	config  *config.Config
	events  chan interface{}
	logger  *log.Logger
	metrics *Metrics
	stats   *Stats
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
func NewMonitor(cfg *config.Config) *Monitor {
	return &Monitor{
		config:  cfg,
		events:  make(chan interface{}, 1000),
		logger:  log.New(os.Stdout, "[SYSTEM] ", log.LstdFlags),
		metrics: NewMetrics(),
		stats: &Stats{
			LastUpdate: time.Now(),
		},
	}
}

// GetEvents returns the events channel
func (m *Monitor) GetEvents() <-chan interface{} {
	return m.events
}

// Start begins system monitoring
func (m *Monitor) Start(ctx context.Context) error {
	// Start monitoring system events
	if err := m.Monitor(ctx); err != nil {
		return fmt.Errorf("failed to start monitoring: %w", err)
	}

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
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

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
				event := map[string]interface{}{
					"timestamp": time.Now().Format(time.RFC3339),
					"source":    "system",
					"event_type": "processes",
					"data":      json.RawMessage(data),
					"host":      hostname,
				}
				m.events <- event
			}

			// Collect network connections
			if conns, err := m.collectNetworkConnections(); err == nil {
				data, _ := json.Marshal(conns)
				event := map[string]interface{}{
					"timestamp": time.Now().Format(time.RFC3339),
					"source":    "system",
					"event_type": "connections",
					"data":      json.RawMessage(data),
					"host":      hostname,
				}
				m.events <- event
			}

			// Collect system info
			if sysInfo, err := m.CollectSystemInfo(); err == nil {
				data, _ := json.Marshal(sysInfo)
				event := map[string]interface{}{
					"timestamp": time.Now().Format(time.RFC3339),
					"source":    "system",
					"event_type": "system_info",
					"data":      json.RawMessage(data),
					"host":      hostname,
				}
				m.events <- event
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
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-events:
			data, err := json.Marshal(event)
			if err != nil {
				m.Error("Error marshaling FIM event: %v", err)
				continue
			}

			severity := "info"
			if event.Type == "Modified" || event.Type == "PermissionChanged" {
				severity = "warning"
			} else if event.Type == "Deleted" {
				severity = "critical"
			}

			evt := map[string]interface{}{
				"timestamp": event.Timestamp.Format(time.RFC3339),
				"source":    "fim",
				"event_type": event.Type,
				"data":      json.RawMessage(data),
				"severity":  severity,
				"host":      hostname,
			}
			m.events <- evt
		}
	}
}

// Monitor starts monitoring system events
func (m *Monitor) Monitor(ctx context.Context) error {
	// Get platform-specific paths
	var logPaths []string
	var serviceNames []string
	var defaultPaths []string

	switch runtime.GOOS {
	case "windows":
		logPaths = m.config.Platform.Windows.EventLogPaths
		serviceNames = m.config.Platform.Windows.ServiceNames
		defaultPaths = m.config.Platform.Windows.DefaultPaths
	case "linux":
		logPaths = m.config.Platform.Linux.SyslogPaths
		serviceNames = m.config.Platform.Linux.ServiceNames
		defaultPaths = m.config.Platform.Linux.DefaultPaths
	case "darwin":
		logPaths = m.config.Platform.Darwin.SystemLogPaths
		serviceNames = m.config.Platform.Darwin.ServiceNames
		defaultPaths = m.config.Platform.Darwin.DefaultPaths
	default:
		logPaths = m.config.Platform.Linux.SyslogPaths
		serviceNames = m.config.Platform.Linux.ServiceNames
		defaultPaths = m.config.Platform.Linux.DefaultPaths
	}

	// Get application log paths based on platform
	var appLogPaths []string
	switch runtime.GOOS {
	case "windows":
		appLogPaths = append(appLogPaths, m.config.System.ApplicationLogs.Windows.Apache...)
		appLogPaths = append(appLogPaths, m.config.System.ApplicationLogs.Windows.Nginx...)
		appLogPaths = append(appLogPaths, m.config.System.ApplicationLogs.Windows.MySQL...)
	case "linux":
		appLogPaths = append(appLogPaths, m.config.System.ApplicationLogs.Linux.Apache...)
		appLogPaths = append(appLogPaths, m.config.System.ApplicationLogs.Linux.Nginx...)
		appLogPaths = append(appLogPaths, m.config.System.ApplicationLogs.Linux.MySQL...)
	case "darwin":
		appLogPaths = append(appLogPaths, m.config.System.ApplicationLogs.Darwin.Apache...)
		appLogPaths = append(appLogPaths, m.config.System.ApplicationLogs.Darwin.Nginx...)
		appLogPaths = append(appLogPaths, m.config.System.ApplicationLogs.Darwin.MySQL...)
	default:
		appLogPaths = append(appLogPaths, m.config.System.ApplicationLogs.Linux.Apache...)
		appLogPaths = append(appLogPaths, m.config.System.ApplicationLogs.Linux.Nginx...)
		appLogPaths = append(appLogPaths, m.config.System.ApplicationLogs.Linux.MySQL...)
	}

	// Start monitoring system logs
	if err := m.monitorSystemLogs(ctx, logPaths); err != nil {
		return fmt.Errorf("failed to monitor system logs: %w", err)
	}

	// Start monitoring application logs
	if err := m.monitorApplicationLogs(ctx, appLogPaths); err != nil {
		return fmt.Errorf("failed to monitor application logs: %w", err)
	}

	// Start monitoring services
	if err := m.monitorServices(ctx, serviceNames); err != nil {
		return fmt.Errorf("failed to monitor services: %w", err)
	}

	// Start monitoring file system
	if err := m.monitorFileSystem(ctx, defaultPaths); err != nil {
		return fmt.Errorf("failed to monitor file system: %w", err)
	}

	// Start osquery if configured
	if m.config.System.OsquerySocketPath != "" {
		if err := m.startOsquery(ctx); err != nil {
			return fmt.Errorf("failed to start osquery: %w", err)
		}
	}

	return nil
}

// monitorSystemLogs monitors system log files
func (m *Monitor) monitorSystemLogs(ctx context.Context, logPaths []string) error {
	for _, path := range logPaths {
		// Skip if path doesn't exist
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		// Create a watcher for each log file
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return fmt.Errorf("failed to create watcher: %w", err)
		}

		// Start monitoring in a goroutine
		go func(path string, watcher *fsnotify.Watcher) {
			defer watcher.Close()

			// Add the log file to the watcher
			if err := watcher.Add(path); err != nil {
				m.Error("Failed to watch log file: %v", err)
				return
			}

			// Open the log file
			file, err := os.Open(path)
			if err != nil {
				m.Error("Failed to open log file: %v", err)
				return
			}
			defer file.Close()

			// Seek to the end of the file
			if _, err := file.Seek(0, 2); err != nil {
				m.Error("Failed to seek to end of log file: %v", err)
				return
			}

			// Create a reader for the file
			reader := bufio.NewReader(file)

			for {
				select {
				case <-ctx.Done():
					return
				case event := <-watcher.Events:
					if event.Op&fsnotify.Write == fsnotify.Write {
						// Read new lines
						for {
							line, err := reader.ReadString('\n')
							if err != nil {
								if err != io.EOF {
									m.Error("Failed to read log line: %v", err)
								}
								break
							}

							// Parse and send the log event
							event := &LogEvent{
								Timestamp: time.Now(),
								Source:    "system",
								Path:      path,
								Content:   strings.TrimSpace(line),
							}

							select {
							case m.events <- event:
							case <-ctx.Done():
								return
							}
						}
					}
				case err := <-watcher.Errors:
					m.Error("Watcher error: %v", err)
				}
			}
		}(path, watcher)
	}

	return nil
}

// monitorApplicationLogs monitors application log files
func (m *Monitor) monitorApplicationLogs(ctx context.Context, logPaths []string) error {
	for _, path := range logPaths {
		// Skip if path doesn't exist
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		// Create a watcher for each log file
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return fmt.Errorf("failed to create watcher: %w", err)
		}

		// Start monitoring in a goroutine
		go func(path string, watcher *fsnotify.Watcher) {
			defer watcher.Close()

			// Add the log file to the watcher
			if err := watcher.Add(path); err != nil {
				m.Error("Failed to watch log file: %v", err)
				return
			}

			// Open the log file
			file, err := os.Open(path)
			if err != nil {
				m.Error("Failed to open log file: %v", err)
				return
			}
			defer file.Close()

			// Seek to the end of the file
			if _, err := file.Seek(0, 2); err != nil {
				m.Error("Failed to seek to end of log file: %v", err)
				return
			}

			// Create a reader for the file
			reader := bufio.NewReader(file)

			// Determine application type from path
			appType := "unknown"
			if strings.Contains(path, "apache") || strings.Contains(path, "httpd") {
				appType = "apache"
			} else if strings.Contains(path, "nginx") {
				appType = "nginx"
			} else if strings.Contains(path, "mysql") {
				appType = "mysql"
			}

			for {
				select {
				case <-ctx.Done():
					return
				case event := <-watcher.Events:
					if event.Op&fsnotify.Write == fsnotify.Write {
						// Read new lines
						for {
							line, err := reader.ReadString('\n')
							if err != nil {
								if err != io.EOF {
									m.Error("Failed to read log line: %v", err)
								}
								break
							}

							// Parse and send the log event
							event := &LogEvent{
								Timestamp: time.Now(),
								Source:    appType,
								Path:      path,
								Content:   strings.TrimSpace(line),
							}

							select {
							case m.events <- event:
							case <-ctx.Done():
								return
							}
						}
					}
				case err := <-watcher.Errors:
					m.Error("Watcher error: %v", err)
				}
			}
		}(path, watcher)
	}

	return nil
}

// monitorServices monitors system services
func (m *Monitor) monitorServices(ctx context.Context, serviceNames []string) error {
	for _, name := range serviceNames {
		// Start monitoring in a goroutine
		go func(name string) {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					// Check service status based on platform
					var status string
					var err error

					switch runtime.GOOS {
					case "windows":
						status, err = m.checkWindowsService(name)
					case "linux":
						status, err = m.checkLinuxService(name)
					case "darwin":
						status, err = m.checkDarwinService(name)
					default:
						status, err = m.checkLinuxService(name)
					}

					if err != nil {
						m.Error("Failed to check service status: %v", err)
						continue
					}

					// Send service status event
					event := &ServiceEvent{
						Timestamp: time.Now(),
						Name:      name,
						Status:    status,
					}

					select {
					case m.events <- event:
					case <-ctx.Done():
						return
					}
				}
			}
		}(name)
	}

	return nil
}

// checkWindowsService checks the status of a Windows service
func (m *Monitor) checkWindowsService(name string) (string, error) {
	cmd := exec.Command("sc", "query", name)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to query service: %w", err)
	}

	// Parse the output to get the service state
	outputStr := string(output)
	if strings.Contains(outputStr, "RUNNING") {
		return "running", nil
	} else if strings.Contains(outputStr, "STOPPED") {
		return "stopped", nil
	} else {
		return "unknown", nil
	}
}

// checkLinuxService checks the status of a Linux service
func (m *Monitor) checkLinuxService(name string) (string, error) {
	cmd := exec.Command("systemctl", "is-active", name)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 3 {
			return "inactive", nil
		}
		return "", fmt.Errorf("failed to check service status: %w", err)
	}

	status := strings.TrimSpace(string(output))
	if status == "active" {
		return "running", nil
	} else {
		return "stopped", nil
	}
}

// checkDarwinService checks the status of a macOS service
func (m *Monitor) checkDarwinService(name string) (string, error) {
	cmd := exec.Command("launchctl", "list", name)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to check service status: %w", err)
	}

	// Parse the output to get the service state
	outputStr := string(output)
	if strings.Contains(outputStr, name) {
		return "running", nil
	} else {
		return "stopped", nil
	}
}

// monitorFileSystem monitors the file system
func (m *Monitor) monitorFileSystem(ctx context.Context, paths []string) error {
	// This is a placeholder for actual file system monitoring
	// In a real implementation, this would use a file system watcher
	// to detect changes in the file system
	return nil
}

// startOsquery starts osquery
func (m *Monitor) startOsquery(ctx context.Context) error {
	// This is a placeholder for starting osquery
	// In a real implementation, this would use a command to start osquery
	return nil
}

// Error logs an error message
func (m *Monitor) Error(msg string, args ...interface{}) {
	m.logger.Printf("[ERROR] "+msg, args...)
}