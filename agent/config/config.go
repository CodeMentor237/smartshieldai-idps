package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config represents the agent configuration
type Config struct {
	AgentID   string         `json:"agent_id"`
	Backend   BackendConfig  `json:"backend"`
	TLS       TLSConfig     `json:"tls"`
	Security  SecurityConfig `json:"security"`
	Monitoring MonitoringConfig `json:"monitoring"`
	Network   NetworkConfig `json:"network"`
	System    SystemConfig  `json:"system"`
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

// NetworkConfig represents network capture settings
type NetworkConfig struct {
	Interface string `json:"interface"`
	BPFFilter string `json:"bpf_filter"`
}

// SystemConfig represents system monitoring settings
type SystemConfig struct {
	LogPaths []string `json:"log_paths"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
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
			Interface: "eth0",
			BPFFilter: "",
		},
		System: SystemConfig{
			LogPaths: []string{
				"/var/log/syslog",
				"/var/log/auth.log",
			},
		},
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