package models

import "time"

// AgentData represents data collected by the agent
type AgentData struct {
	Type      string                 `json:"type"`
	Timestamp time.Time             `json:"timestamp"`
	Source    string                `json:"source"`
	RawData   map[string]interface{} `json:"raw_data"`
} 