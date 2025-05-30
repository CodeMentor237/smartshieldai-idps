package config

import "time"

// Config represents the agent configuration
type Config struct {
	BackendURL            string          `json:"backend_url"`
	DataCollectionInterval time.Duration   `json:"data_collection_interval"`
	LDAP                  LDAPConfig      `json:"ldap"`
	Cloud                 CloudConfig     `json:"cloud"`
	ML                    MLConfig        `json:"ml"`
	Prevention            PreventionConfig `json:"prevention"`
}

// LDAPConfig represents LDAP configuration
type LDAPConfig struct {
	Enabled  bool   `json:"enabled"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	BaseDN   string `json:"base_dn"`
	BindDN   string `json:"bind_dn"`
	Password string `json:"password"`
	Timeout  time.Duration `json:"timeout"`
}

// CloudConfig represents cloud configuration
type CloudConfig struct {
	Enabled bool     `json:"enabled"`
	AWS     AWSConfig `json:"aws"`
}

// AWSConfig represents AWS configuration
type AWSConfig struct {
	Region          string `json:"region"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

// MLConfig represents ML configuration
type MLConfig struct {
	Enabled    bool   `json:"enabled"`
	ModelPath  string `json:"model_path"`
	InputSize  int    `json:"input_size"`
	HiddenSize int    `json:"hidden_size"`
	BatchSize  int    `json:"batch_size"`
}

// PreventionConfig represents prevention configuration
type PreventionConfig struct {
	Enabled            bool          `json:"enabled"`
	DryRun            bool          `json:"dry_run"`
	AutoRollback      bool          `json:"auto_rollback"`
	ActionTimeout     time.Duration `json:"action_timeout"`
	MaxConcurrentActions int         `json:"max_concurrent_actions"`
} 