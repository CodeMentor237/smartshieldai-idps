package system

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
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

// Monitor handles system monitoring
type Monitor struct {
	config    MonitorConfig
	fim       *fim.Monitor
	logsChan  chan<- LogData
	stopChan  chan struct{}
	hostname  string
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
func NewMonitor(config MonitorConfig) (*Monitor, error) {
	info, err := host.Info()
	if err != nil {
		return nil, fmt.Errorf("error getting host info: %v", err)
	}

	return &Monitor{
		config:   config,
		stopChan: make(chan struct{}),
		hostname: info.Hostname,
	}, nil
}

// Start begins system monitoring
func (m *Monitor) Start(logsChan chan<- LogData, ctx context.Context) error {
	m.logsChan = logsChan

	// Initialize FIM
	fimEvents := make(chan fim.Event, 1000)
	fimMonitor, err := fim.NewMonitor(m.config.FIMConfig, fimEvents)
	if err != nil {
		return fmt.Errorf("error initializing FIM: %v", err)
	}
	m.fim = fimMonitor

	// Start FIM
	if err := m.fim.Start(); err != nil {
		return fmt.Errorf("error starting FIM: %v", err)
	}

	// Start system queries
	go m.queryLoop(ctx)

	// Process FIM events
	go m.processFIMEvents(fimEvents, ctx)

	return nil
}

// Stop stops monitoring
func (m *Monitor) Stop() {
	if m.fim != nil {
		m.fim.Stop()
	}
	close(m.stopChan)
}

// queryLoop performs periodic system queries
func (m *Monitor) queryLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.QueryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			// Collect process information
			if procs, err := m.collectProcessInfo(); err == nil {
				data, _ := json.Marshal(procs)
				m.logsChan <- LogData{
					Timestamp: time.Now(),
					Source:    "system",
					EventType: "processes",
					Data:     data,
					Host:     m.hostname,
				}
			}

			// Collect network connections
			if conns, err := m.collectNetworkConnections(); err == nil {
				data, _ := json.Marshal(conns)
				m.logsChan <- LogData{
					Timestamp: time.Now(),
					Source:    "system",
					EventType: "connections",
					Data:     data,
					Host:     m.hostname,
				}
			}

			// Collect system info
			if sysInfo, err := m.collectSystemInfo(); err == nil {
				data, _ := json.Marshal(sysInfo)
				m.logsChan <- LogData{
					Timestamp: time.Now(),
					Source:    "system",
					EventType: "system_info",
					Data:     data,
					Host:     m.hostname,
				}
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

// collectSystemInfo gathers system information
func (m *Monitor) collectSystemInfo() (map[string]interface{}, error) {
	info, err := host.Info()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"hostname":     info.Hostname,
		"os":          info.OS,
		"platform":    info.Platform,
		"platformFamily": info.PlatformFamily,
		"version":     info.PlatformVersion,
		"kernelVersion": info.KernelVersion,
		"uptime":      info.Uptime,
	}, nil
}

// processFIMEvents handles file integrity monitoring events
func (m *Monitor) processFIMEvents(events chan fim.Event, ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
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

			m.logsChan <- LogData{
				Timestamp: event.Timestamp,
				Source:    "fim",
				EventType: event.Type,
				Data:     data,
				Severity: severity,
				Host:     m.hostname,
			}
		}
	}
}