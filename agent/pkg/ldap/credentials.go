package ldap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CredentialManager manages LDAP credentials securely
type CredentialManager struct {
	key        []byte
	mu         sync.RWMutex
	configPath string
}

// NewCredentialManager creates a new credential manager
func NewCredentialManager(configPath string) (*CredentialManager, error) {
	// Generate or load encryption key
	keyPath := filepath.Join(filepath.Dir(configPath), ".ldap_key")
	key, err := loadOrGenerateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load/generate key: %v", err)
	}

	return &CredentialManager{
		key:        key,
		configPath: configPath,
	}, nil
}

// SaveCredentials encrypts and saves LDAP credentials
func (m *CredentialManager) SaveCredentials(config Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(m.configPath), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Encrypt password
	encryptedPassword, err := m.encrypt(config.Password)
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %v", err)
	}

	// Create secure config
	secureConfig := struct {
		Server   string `json:"server"`
		Port     int    `json:"port"`
		BaseDN   string `json:"base_dn"`
		BindDN   string `json:"bind_dn"`
		Password string `json:"password"`
		UseTLS   bool   `json:"use_tls"`
		Timeout  string `json:"timeout"`
	}{
		Server:   config.Server,
		Port:     config.Port,
		BaseDN:   config.BaseDN,
		BindDN:   config.BindDN,
		Password: encryptedPassword,
		UseTLS:   config.UseTLS,
		Timeout:  config.Timeout.String(),
	}

	// Save to file with restricted permissions
	data, err := json.MarshalIndent(secureConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(m.configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// LoadCredentials loads and decrypts LDAP credentials
func (m *CredentialManager) LoadCredentials() (*Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Read config file
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse config
	var secureConfig struct {
		Server   string `json:"server"`
		Port     int    `json:"port"`
		BaseDN   string `json:"base_dn"`
		BindDN   string `json:"bind_dn"`
		Password string `json:"password"`
		UseTLS   bool   `json:"use_tls"`
		Timeout  string `json:"timeout"`
	}

	if err := json.Unmarshal(data, &secureConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	// Decrypt password
	password, err := m.decrypt(secureConfig.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt password: %v", err)
	}

	// Parse timeout
	timeout, err := time.ParseDuration(secureConfig.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timeout: %v", err)
	}

	return &Config{
		Server:   secureConfig.Server,
		Port:     secureConfig.Port,
		BaseDN:   secureConfig.BaseDN,
		BindDN:   secureConfig.BindDN,
		Password: password,
		UseTLS:   secureConfig.UseTLS,
		Timeout:  timeout,
	}, nil
}

// encrypt encrypts data using AES-GCM
func (m *CredentialManager) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts data using AES-GCM
func (m *CredentialManager) decrypt(encrypted string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// loadOrGenerateKey loads an existing key or generates a new one
func loadOrGenerateKey(path string) ([]byte, error) {
	// Try to load existing key
	if data, err := os.ReadFile(path); err == nil {
		return data, nil
	}

	// Generate new key
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	// Save key
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, err
	}

	return key, nil
} 