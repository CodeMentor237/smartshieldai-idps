package prevention

import (
	"fmt"
	"time"
)

// Config represents prevention layer configuration
type Config struct {
	EnableBlockIP     bool          `json:"enable_block_ip" yaml:"enable_block_ip"`
	EnableProcessKill bool          `json:"enable_process_kill" yaml:"enable_process_kill"`
	WhitelistedIPs   []string      `json:"whitelisted_ips" yaml:"whitelist.ips"`
	WhitelistedProcs []string      `json:"whitelisted_procs" yaml:"whitelist.processes"`
	RollbackTimeout  time.Duration `json:"rollback_timeout" yaml:"rollback_timeout"`
	LogActions       bool          `json:"log_actions" yaml:"log_actions"`
	DryRun          bool          `json:"dry_run" yaml:"dry_run"`
	AlertThreshold  float64       `json:"alert_threshold" yaml:"alert_threshold"`
	
	// Elasticsearch configuration
	ESAddrs []string `json:"es_addrs" yaml:"es_addrs"`
	ESUser  string   `json:"es_user" yaml:"es_user"`
	ESPass  string   `json:"es_pass" yaml:"es_pass"`
	ESIndex string   `json:"es_index" yaml:"es_index"`
}

// Validate ensures the configuration is valid
func (c *Config) Validate() error {
	if c.EnableBlockIP || c.EnableProcessKill {
		if c.RollbackTimeout == 0 {
			return fmt.Errorf("rollback timeout must be set when prevention actions are enabled")
		}
		if c.AlertThreshold <= 0 || c.AlertThreshold > 1 {
			return fmt.Errorf("alert threshold must be between 0 and 1")
		}
	}

	if len(c.ESAddrs) == 0 && !c.DryRun {
		return fmt.Errorf("elasticsearch configuration required when not in dry-run mode")
	}

	return nil
}

// DefaultConfig returns a default prevention configuration
func DefaultConfig() Config {
	return Config{
		EnableBlockIP:     false,
		EnableProcessKill: false,
		RollbackTimeout:   30 * time.Second,
		LogActions:        true,
		DryRun:           true,
		AlertThreshold:    0.9,
		WhitelistedIPs:   []string{"127.0.0.1", "::1"},
		WhitelistedProcs: []string{"systemd", "sshd", "dockerd"},
	}
}
