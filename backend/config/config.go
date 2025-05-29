package config

import (
	"crypto/tls"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds the application configuration
type Config struct {
	Port           string
	RedisURL       string
	TLSCertFile    string
	TLSKeyFile     string
	APITokenSecret string

	// Elasticsearch configuration
	ElasticsearchAddrs []string
	ElasticsearchUser  string
	ElasticsearchPass  string
	ElasticsearchIndex string
	YaraRulesPath     string
}

// LoadConfig loads the configuration from environment variables
func LoadConfig() (*Config, error) {
	// Load .env file if it exists
	godotenv.Load()

	config := &Config{
		Port:           getEnv("PORT", "8443"),
		RedisURL:       getEnv("REDIS_URL", "redis://localhost:6379"),
		TLSCertFile:    getEnv("TLS_CERT_FILE", "certs/server.crt"),
		TLSKeyFile:     getEnv("TLS_KEY_FILE", "certs/server.key"),
		APITokenSecret: getEnv("API_TOKEN_SECRET", "your-secret-key"),

		// Add Elasticsearch configuration
		ElasticsearchAddrs: strings.Split(getEnv("ES_ADDRESSES", "http://localhost:9200"), ","),
		ElasticsearchUser:  getEnv("ES_USERNAME", "elastic"),
		ElasticsearchPass:  getEnv("ES_PASSWORD", ""),
		ElasticsearchIndex: getEnv("ES_INDEX", "threats"),
		YaraRulesPath:      getEnv("YARA_RULES_PATH", "rules"),
	}

	return config, nil
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