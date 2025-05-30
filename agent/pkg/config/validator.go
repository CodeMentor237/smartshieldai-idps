package config

import (
	"fmt"
	"net/url"
)

// ConfigValidator validates the agent configuration
type ConfigValidator struct {
	config *Config
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator(config *Config) *ConfigValidator {
	return &ConfigValidator{
		config: config,
	}
}

// Validate performs comprehensive configuration validation
func (v *ConfigValidator) Validate() error {
	if err := v.validateBasicConfig(); err != nil {
		return fmt.Errorf("basic config validation failed: %v", err)
	}

	if err := v.validateLDAPConfig(); err != nil {
		return fmt.Errorf("LDAP config validation failed: %v", err)
	}

	if err := v.validateCloudConfig(); err != nil {
		return fmt.Errorf("cloud config validation failed: %v", err)
	}

	if err := v.validateMLConfig(); err != nil {
		return fmt.Errorf("ML config validation failed: %v", err)
	}

	if err := v.validatePreventionConfig(); err != nil {
		return fmt.Errorf("prevention config validation failed: %v", err)
	}

	return nil
}

// validateBasicConfig validates basic configuration settings
func (v *ConfigValidator) validateBasicConfig() error {
	if v.config.BackendURL == "" {
		return fmt.Errorf("backend URL is required")
	}

	if _, err := url.Parse(v.config.BackendURL); err != nil {
		return fmt.Errorf("invalid backend URL: %v", err)
	}

	if v.config.DataCollectionInterval <= 0 {
		return fmt.Errorf("data collection interval must be positive")
	}

	return nil
}

// validateLDAPConfig validates LDAP configuration
func (v *ConfigValidator) validateLDAPConfig() error {
	if !v.config.LDAP.Enabled {
		return nil
	}

	if v.config.LDAP.Server == "" {
		return fmt.Errorf("LDAP server is required when LDAP is enabled")
	}

	if v.config.LDAP.Port <= 0 || v.config.LDAP.Port > 65535 {
		return fmt.Errorf("invalid LDAP port")
	}

	if v.config.LDAP.BaseDN == "" {
		return fmt.Errorf("LDAP base DN is required")
	}

	if v.config.LDAP.BindDN == "" {
		return fmt.Errorf("LDAP bind DN is required")
	}

	if v.config.LDAP.Password == "" {
		return fmt.Errorf("LDAP password is required")
	}

	if v.config.LDAP.Timeout <= 0 {
		return fmt.Errorf("LDAP timeout must be positive")
	}

	return nil
}

// validateCloudConfig validates cloud configuration
func (v *ConfigValidator) validateCloudConfig() error {
	if !v.config.Cloud.Enabled {
		return nil
	}

	if v.config.Cloud.AWS.Region == "" {
		return fmt.Errorf("AWS region is required when cloud is enabled")
	}

	if v.config.Cloud.AWS.AccessKeyID == "" {
		return fmt.Errorf("AWS access key ID is required")
	}

	if v.config.Cloud.AWS.SecretAccessKey == "" {
		return fmt.Errorf("AWS secret access key is required")
	}

	return nil
}

// validateMLConfig validates ML configuration
func (v *ConfigValidator) validateMLConfig() error {
	if !v.config.ML.Enabled {
		return nil
	}

	if v.config.ML.ModelPath == "" {
		return fmt.Errorf("ML model path is required when ML is enabled")
	}

	if v.config.ML.InputSize <= 0 {
		return fmt.Errorf("ML input size must be positive")
	}

	if v.config.ML.HiddenSize <= 0 {
		return fmt.Errorf("ML hidden size must be positive")
	}

	if v.config.ML.BatchSize <= 0 {
		return fmt.Errorf("ML batch size must be positive")
	}

	return nil
}

// validatePreventionConfig validates prevention configuration
func (v *ConfigValidator) validatePreventionConfig() error {
	if !v.config.Prevention.Enabled {
		return nil
	}

	if v.config.Prevention.DryRun && v.config.Prevention.AutoRollback {
		return fmt.Errorf("auto rollback cannot be enabled in dry run mode")
	}

	if v.config.Prevention.ActionTimeout <= 0 {
		return fmt.Errorf("prevention action timeout must be positive")
	}

	if v.config.Prevention.MaxConcurrentActions <= 0 {
		return fmt.Errorf("max concurrent actions must be positive")
	}

	return nil
} 