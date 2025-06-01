package models

import (
	"encoding/json"
	"time"
)

// AgentData represents the unified data structure for all agent events
type AgentData struct {
	ID          string          `json:"id"`
	AgentID     string          `json:"agent_id"`
	Timestamp   time.Time       `json:"timestamp"`
	DataType    string          `json:"data_type"` // "network", "system", or "process"
	RawData     json.RawMessage `json:"raw_data"`
	Source      string          `json:"source"`
	Destination string          `json:"destination,omitempty"`
	EventType   string          `json:"event_type,omitempty"`
	Protocol    string          `json:"protocol,omitempty"`
	Severity    string          `json:"severity,omitempty"`
	// Process-specific fields
	ProcessID   string          `json:"process_id,omitempty"`
	ProcessName string          `json:"process_name,omitempty"`
	CommandLine string          `json:"command_line,omitempty"`
	ParentID    string          `json:"parent_id,omitempty"`
	UserID      string          `json:"user_id,omitempty"`
	// Network-specific fields
	Port        int            `json:"port,omitempty"`
	// File-specific fields
	FilePath    string          `json:"file_path,omitempty"`
	FileHash    string          `json:"file_hash,omitempty"`
	// Authentication-specific fields
	Username    string          `json:"username,omitempty"`
	Domain      string          `json:"domain,omitempty"`
	// Cloud-specific fields
	CloudProvider string         `json:"cloud_provider,omitempty"`
	ResourceID    string         `json:"resource_id,omitempty"`
	// Additional metadata
	Labels      map[string]string `json:"labels,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
}

// NetworkData represents network packet data from the agent
type NetworkData struct {
	Timestamp    time.Time     `json:"timestamp"`
	Source      string        `json:"source"`
	Destination string        `json:"destination"`
	Protocol    string        `json:"protocol"`
	Length      int          `json:"length"`
	PacketType  string        `json:"packet_type"`
	TCPInfo     *TCPMetadata  `json:"tcp_info,omitempty"`
	UDPInfo     *UDPMetadata  `json:"udp_info,omitempty"`
	PayloadSize int          `json:"payload_size,omitempty"`
}

// SystemData represents system log data from the agent
type SystemData struct {
	Timestamp time.Time       `json:"timestamp"`
	Source    string         `json:"source"`
	EventType string         `json:"event_type"`
	Data      json.RawMessage `json:"data"`
	Severity  string         `json:"severity,omitempty"`
	Host      string         `json:"host,omitempty"`
}

// TCPMetadata represents TCP-specific information
type TCPMetadata struct {
	SrcPort    uint16 `json:"src_port"`
	DstPort    uint16 `json:"dst_port"`
	Seq        uint32 `json:"seq"`
	Ack        uint32 `json:"ack"`
	WindowSize uint16 `json:"window_size"`
	Flags      string `json:"flags"`
}

// UDPMetadata represents UDP-specific information
type UDPMetadata struct {
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	Length  uint16 `json:"length"`
}