package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// PlatformConfig holds platform-specific configuration
type PlatformConfig struct {
	Windows struct {
		EventLogPaths []string `json:"event_log_paths"`
		ServiceNames  []string `json:"service_names"`
		DefaultPaths  []string `json:"default_paths"`
	} `json:"windows"`
	Linux struct {
		SyslogPaths   []string `json:"syslog_paths"`
		ServiceNames  []string `json:"service_names"`
		DefaultPaths  []string `json:"default_paths"`
	} `json:"linux"`
	Darwin struct {
		SystemLogPaths []string `json:"system_log_paths"`
		ServiceNames   []string `json:"service_names"`
		DefaultPaths   []string `json:"default_paths"`
	} `json:"darwin"`
}

// ApplicationLogPaths holds platform-specific application log paths
type ApplicationLogPaths struct {
	Windows struct {
		Apache []string `json:"apache"`
		Nginx  []string `json:"nginx"`
		MySQL  []string `json:"mysql"`
	} `json:"windows"`
	Linux struct {
		Apache []string `json:"apache"`
		Nginx  []string `json:"nginx"`
		MySQL  []string `json:"mysql"`
	} `json:"linux"`
	Darwin struct {
		Apache []string `json:"apache"`
		Nginx  []string `json:"nginx"`
		MySQL  []string `json:"mysql"`
	} `json:"darwin"`
}

// Config represents the agent configuration
type Config struct {
	AgentID   string         `json:"agent_id"`
	Backend   BackendConfig  `json:"backend"`
	TLS       TLSConfig     `json:"tls"`
	Security  SecurityConfig `json:"security"`
	Monitoring MonitoringConfig `json:"monitoring"`
	Network   NetworkConfig `json:"network"`
	System    SystemConfig  `json:"system"`
	Cloud     CloudConfig   `json:"cloud"`
	Platform  PlatformConfig `json:"platform"`
}

// BackendConfig represents backend connection settings
type BackendConfig struct {
	URL     string        `json:"url"`
	Timeout time.Duration `json:"timeout"`
}

// TLSConfig represents TLS settings
type TLSConfig struct {
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

// SecurityConfig represents security settings
type SecurityConfig struct {
	EnablePayloadEncryption bool    `json:"enable_payload_encryption"`
	RateLimit              float64 `json:"rate_limit"`
	RateLimitBurst         float64 `json:"rate_limit_burst"`
	EncryptionKey          string  `json:"encryption_key"`
}

// MonitoringConfig represents monitoring settings
type MonitoringConfig struct {
	MetricsInterval     time.Duration `json:"metrics_interval"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	HealthCheckPort     int          `json:"health_check_port"`
}

// NetworkConfig holds network capture configuration
type NetworkConfig struct {
	Interfaces    []string `yaml:"interfaces"`
	CaptureFilter string   `yaml:"capture_filter"`
	MaxPacketSize int      `yaml:"max_packet_size"`
	Promiscuous    bool     `yaml:"promiscuous"`
	BufferSize     int      `yaml:"buffer_size"`
	Timeout        time.Duration `yaml:"timeout"`
	StatsInterval  time.Duration `yaml:"stats_interval"`
	GeoIPDBPath    string   `yaml:"geoip_db_path"`
}

// SystemConfig represents system monitoring settings
type SystemConfig struct {
	LogPaths            []string `json:"log_paths"`
	OsquerySocketPath   string   `json:"osquery_socket_path"`
	ApplicationLogs     ApplicationLogPaths `json:"application_logs"`
}

type CloudConfig struct {
	AWS struct {
		Region          string `json:"region"`
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
		SessionToken    string `json:"session_token,omitempty"`
		RoleARN         string `json:"role_arn,omitempty"`
	} `json:"aws"`
	CloudTrail struct {
		Enabled      bool     `json:"enabled"`
		EventTypes   []string `json:"event_types"`
		MaxResults   int32    `json:"max_results"`
		PollInterval string   `json:"poll_interval"`
	} `json:"cloudtrail"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	// Get default interface based on OS
	defaultInterface := "eth0"
	if runtime.GOOS == "darwin" {
		defaultInterface = "en0"
	} else if runtime.GOOS == "windows" {
		defaultInterface = "Ethernet"
	}

	// Platform-specific default paths
	platformConfig := PlatformConfig{}
	
	// Windows defaults
	platformConfig.Windows.EventLogPaths = []string{
		"C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
		"C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
		"C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
	}
	platformConfig.Windows.ServiceNames = []string{
		"Apache2.4",
		"MySQL80",
		"nginx",
	}
	platformConfig.Windows.DefaultPaths = []string{
		"C:\\Windows\\System32",
		"C:\\Program Files",
		"C:\\Program Files (x86)",
		"C:\\Users",
	}

	// Linux defaults
	platformConfig.Linux.SyslogPaths = []string{
		"/var/log/syslog",
		"/var/log/auth.log",
		"/var/log/messages",
	}
	platformConfig.Linux.ServiceNames = []string{
		"apache2",
		"mysql",
		"nginx",
	}
	platformConfig.Linux.DefaultPaths = []string{
		"/etc",
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/var/log",
	}

	// macOS defaults
	platformConfig.Darwin.SystemLogPaths = []string{
		"/var/log/system.log",
		"/var/log/auth.log",
		"/var/log/install.log",
	}
	platformConfig.Darwin.ServiceNames = []string{
		"org.apache.httpd",
		"com.mysql.mysqld",
		"org.nginx.nginx",
	}
	platformConfig.Darwin.DefaultPaths = []string{
		"/etc",
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/var/log",
		"/Applications",
	}

	// Application log paths
	appLogs := ApplicationLogPaths{}
	
	// Windows application logs
	appLogs.Windows.Apache = []string{
		"C:\\Program Files\\Apache\\logs\\access.log",
		"C:\\Program Files\\Apache\\logs\\error.log",
		"C:\\xampp\\apache\\logs\\access.log",
		"C:\\xampp\\apache\\logs\\error.log",
	}
	appLogs.Windows.Nginx = []string{
		"C:\\Program Files\\nginx\\logs\\access.log",
		"C:\\Program Files\\nginx\\logs\\error.log",
	}
	appLogs.Windows.MySQL = []string{
		"C:\\Program Files\\MySQL\\Data\\mysql.log",
		"C:\\xampp\\mysql\\data\\mysql.log",
	}

	// Linux application logs
	appLogs.Linux.Apache = []string{
		"/var/log/apache2/access.log",
		"/var/log/apache2/error.log",
		"/var/log/httpd/access_log",
		"/var/log/httpd/error_log",
	}
	appLogs.Linux.Nginx = []string{
		"/var/log/nginx/access.log",
		"/var/log/nginx/error.log",
	}
	appLogs.Linux.MySQL = []string{
		"/var/log/mysql/error.log",
		"/var/log/mysql/mysql.log",
		"/var/log/mysqld.log",
	}

	// macOS application logs
	appLogs.Darwin.Apache = []string{
		"/var/log/apache2/access.log",
		"/var/log/apache2/error.log",
		"/private/var/log/apache2/access.log",
		"/private/var/log/apache2/error.log",
	}
	appLogs.Darwin.Nginx = []string{
		"/var/log/nginx/access.log",
		"/var/log/nginx/error.log",
		"/private/var/log/nginx/access.log",
		"/private/var/log/nginx/error.log",
	}
	appLogs.Darwin.MySQL = []string{
		"/var/log/mysql/error.log",
		"/var/log/mysql/mysql.log",
		"/private/var/log/mysql/error.log",
		"/private/var/log/mysql/mysql.log",
	}

	// Get platform-specific log paths
	var logPaths []string
	switch runtime.GOOS {
	case "windows":
		logPaths = platformConfig.Windows.EventLogPaths
	case "linux":
		logPaths = platformConfig.Linux.SyslogPaths
	case "darwin":
		logPaths = platformConfig.Darwin.SystemLogPaths
	default:
		logPaths = platformConfig.Linux.SyslogPaths // fallback to Linux paths
	}

	return &Config{
		AgentID: "agent-001",
		Backend: BackendConfig{
			URL:     "https://localhost:8080/api/v1/data",
			Timeout: 10 * time.Second,
		},
		TLS: TLSConfig{
			InsecureSkipVerify: false,
		},
		Security: SecurityConfig{
			EnablePayloadEncryption: true,
			RateLimit:              100,
			RateLimitBurst:         200,
			EncryptionKey:          "your-32-byte-encryption-key-here",
		},
		Monitoring: MonitoringConfig{
			MetricsInterval:     30 * time.Second,
			HealthCheckInterval: 60 * time.Second,
			HealthCheckPort:     8081,
		},
		Network: NetworkConfig{
			Interfaces:     []string{defaultInterface},
			MaxPacketSize:  65535,
			CaptureFilter:  "",
			Promiscuous:    true,
			BufferSize:     1024 * 1024, // 1MB buffer
			Timeout:        time.Second * 30,
			StatsInterval:  time.Second * 30,
			GeoIPDBPath:    "GeoLite2-City.mmdb",
		},
		System: SystemConfig{
			LogPaths:          logPaths,
			OsquerySocketPath: "",
			ApplicationLogs:   appLogs,
		},
		Platform: platformConfig,
	}
}

// Load loads the configuration from a file
func Load() (*Config, error) {
	// For now, return default configuration
	// In production, this would load from a file
	return DefaultConfig(), nil
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	// Start with default configuration
	config := DefaultConfig()

	// Read configuration file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	// Parse configuration
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("error parsing config file: %v", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.AgentID == "" {
		return fmt.Errorf("agent_id is required")
	}

	if c.Backend.URL == "" {
		return fmt.Errorf("backend_url is required")
	}

	if c.Security.EnablePayloadEncryption && c.Security.EncryptionKey == "" {
		return fmt.Errorf("encryption_key is required when payload encryption is enabled")
	}

	return nil
}

// SaveConfig saves the configuration to a file
func (c *Config) SaveConfig(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("error creating config directory: %v", err)
	}

	// Marshal configuration
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling config: %v", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("error writing config file: %v", err)
	}

	return nil
} 