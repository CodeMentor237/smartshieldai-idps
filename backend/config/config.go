package config

import (
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Server struct {
		Port string `yaml:"port"`
		TLS  struct {
			Enabled  bool   `yaml:"enabled"`
			CertPath string `yaml:"cert_path"`
			KeyPath  string `yaml:"key_path"`
		} `yaml:"tls"`
	} `yaml:"server"`

	Redis struct {
		PoolSize      int `yaml:"pool_size"`
		MinIdleConns  int `yaml:"min_idle_conns"`
		MaxRetries    int `yaml:"max_retries"`
	} `yaml:"redis"`

	Elasticsearch struct {
		MaxRetries int           `yaml:"max_retries"`
		Timeout    time.Duration `yaml:"timeout"`
	} `yaml:"elasticsearch"`

	Detection struct {
		YaraRulesPath       string        `yaml:"yara_rules_path"`
		ScanTimeout         time.Duration `yaml:"scan_timeout"`
		MaxConcurrentScans  int           `yaml:"max_concurrent_scans"`
		ML                  struct {
			Enabled          bool    `yaml:"enabled"`
			ModelPath        string  `yaml:"model_path"`
			InputSize        int     `yaml:"input_size"`
			HiddenSize       int     `yaml:"hidden_size"`
			NumLayers        int     `yaml:"num_layers"`
			DropoutRate      float64 `yaml:"dropout_rate"`
			LearningRate     float64 `yaml:"learning_rate"`
			BatchSize        int     `yaml:"batch_size"`
			Epochs           int     `yaml:"epochs"`
			MinAccuracy      float64 `yaml:"min_accuracy"`
			MaxFalsePositive float64 `yaml:"max_false_positive"`
			MaxFalseNegative float64 `yaml:"max_false_negative"`
			UpdateInterval   string  `yaml:"update_interval"`
			RetrainInterval  string  `yaml:"retrain_interval"`
		} `yaml:"ml"`
	} `yaml:"detection"`

	Security struct {
		RateLimit       int `yaml:"rate_limit"`
		RateLimitBurst  int `yaml:"rate_limit_burst"`
		MaxRequestSize  int `yaml:"max_request_size"`
	} `yaml:"security"`

	// Runtime configuration
	RedisURL            string
	ElasticsearchAddrs  []string
	ElasticsearchUser   string
	ElasticsearchPass   string
	ElasticsearchIndex  string
}

// LoadConfig loads the configuration from a file
func LoadConfig() (*Config, error) {
	// Default config file path
	configPath := "config/config.yaml"

	// Check if config path is set in environment
	if envPath := os.Getenv("CONFIG_PATH"); envPath != "" {
		configPath = envPath
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	// Parse config
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("error parsing config file: %v", err)
	}

	// Load environment variables
	cfg.RedisURL = os.Getenv("REDIS_URL")
	if cfg.RedisURL == "" {
		cfg.RedisURL = "redis://localhost:6379"
	}

	cfg.ElasticsearchAddrs = []string{os.Getenv("ELASTICSEARCH_URL")}
	if cfg.ElasticsearchAddrs[0] == "" {
		cfg.ElasticsearchAddrs = []string{"http://localhost:9200"}
	}

	cfg.ElasticsearchUser = os.Getenv("ELASTICSEARCH_USER")
	cfg.ElasticsearchPass = os.Getenv("ELASTICSEARCH_PASS")
	cfg.ElasticsearchIndex = os.Getenv("ELASTICSEARCH_INDEX")
	if cfg.ElasticsearchIndex == "" {
		cfg.ElasticsearchIndex = "threats"
	}

	return &cfg, nil
}

// GetTLSConfig returns a TLS configuration for the server
func GetTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}