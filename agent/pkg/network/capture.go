package network

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// CaptureConfig holds configuration for packet capture
type CaptureConfig struct {
	DeviceName     string
	SnapLen        int32
	BPFFilter      string
	BufferSize     int
	ChannelSize    int
	CollectPayload bool
}

// DefaultConfig returns a default capture configuration
func DefaultConfig(deviceName string) CaptureConfig {
	return CaptureConfig{
		DeviceName:     deviceName,
		SnapLen:        1600,
		BPFFilter:      "tcp or udp",
		BufferSize:     2 * 1024 * 1024, // 2MB buffer
		ChannelSize:    1000,
		CollectPayload: false,
	}
}

// PacketData represents normalized network packet data in JSON format
type PacketData struct {
	Timestamp    time.Time         `json:"timestamp"`
	Source       string           `json:"source"`
	Destination  string           `json:"destination"`
	Protocol     string           `json:"protocol"`
	Length       int             `json:"length"`
	Info         string           `json:"info"`
	PacketType   string           `json:"packet_type"`
	TCPInfo      *TCPMetadata     `json:"tcp_info,omitempty"`
	UDPInfo      *UDPMetadata     `json:"udp_info,omitempty"`
	PayloadSize  int             `json:"payload_size,omitempty"`
}

// TCPMetadata contains TCP-specific information
type TCPMetadata struct {
	SrcPort    uint16 `json:"src_port"`
	DstPort    uint16 `json:"dst_port"`
	Seq        uint32 `json:"seq"`
	Ack        uint32 `json:"ack"`
	WindowSize uint16 `json:"window_size"`
	Flags      string `json:"flags"`
}

// UDPMetadata contains UDP-specific information
type UDPMetadata struct {
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	Length  uint16 `json:"length"`
}

// Capture represents a network capture session
type Capture struct {
	handle      *pcap.Handle
	config      CaptureConfig
	stopped     bool
	stats       CaptureStats
}

// CaptureStats holds packet capture statistics
type CaptureStats struct {
	PacketsReceived  uint64
	PacketsDropped   uint64
	PacketsFiltered  uint64
}

// NewCapture creates a new packet capture session with the given configuration
func NewCapture(config CaptureConfig) (*Capture, error) {
	// Check if we have permission to capture
	handle, err := pcap.OpenLive(config.DeviceName, config.SnapLen, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("error opening device %s (may require root/admin privileges): %v", config.DeviceName, err)
	}

	// Apply BPF filter if specified
	if config.BPFFilter != "" {
		if err := handle.SetBPFFilter(config.BPFFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("error setting BPF filter: %v", err)
		}
	}

	return &Capture{
		handle:  handle,
		config:  config,
	}, nil
}

// Start begins capturing packets and sends them to the provided channel
func (c *Capture) Start(packets chan<- PacketData) error {
	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true
	
	go func() {
		for packet := range packetSource.Packets() {
			if c.stopped {
				break
			}

			c.stats.PacketsReceived++

			// Basic packet data
			packetData := PacketData{
				Timestamp:   packet.Metadata().Timestamp,
				Length:      packet.Metadata().Length,
				PacketType: "UNKNOWN",
			}

			// Extract network layer information
			if networkLayer := packet.NetworkLayer(); networkLayer != nil {
				packetData.Source = networkLayer.NetworkFlow().Src().String()
				packetData.Destination = networkLayer.NetworkFlow().Dst().String()
				packetData.Protocol = networkLayer.LayerType().String()
			}

			// Extract transport layer information
			if transportLayer := packet.TransportLayer(); transportLayer != nil {
				switch t := transportLayer.(type) {
				case *layers.TCP:
					packetData.PacketType = "TCP"
					packetData.TCPInfo = &TCPMetadata{
						SrcPort:    uint16(t.SrcPort),
						DstPort:    uint16(t.DstPort),
						Seq:        t.Seq,
						Ack:        t.Ack,
						WindowSize: t.Window,
						Flags:      getTCPFlags(t),
					}
				case *layers.UDP:
					packetData.PacketType = "UDP"
					packetData.UDPInfo = &UDPMetadata{
						SrcPort: uint16(t.SrcPort),
						DstPort: uint16(t.DstPort),
						Length:  uint16(len(t.Payload)),
					}
				}
			}

			// Include payload size if configured
			if c.config.CollectPayload {
				if app := packet.ApplicationLayer(); app != nil {
					packetData.PayloadSize = len(app.Payload())
				}
			}

			// Try to send packet data, drop if channel is full
			select {
			case packets <- packetData:
			default:
				c.stats.PacketsDropped++
			}
		}
	}()

	return nil
}

// Stop stops the packet capture
func (c *Capture) Stop() {
	c.stopped = true
	if c.handle != nil {
		c.handle.Close()
	}
}

// GetStats returns current capture statistics
func (c *Capture) GetStats() CaptureStats {
	if stats, err := c.handle.Stats(); err == nil {
		c.stats.PacketsReceived = uint64(stats.PacketsReceived)
		c.stats.PacketsDropped = uint64(stats.PacketsDropped)
	}
	return c.stats
}

// getTCPFlags returns a string representation of TCP flags
func getTCPFlags(tcp *layers.TCP) string {
	var flags []string
	if tcp.FIN { flags = append(flags, "FIN") }
	if tcp.SYN { flags = append(flags, "SYN") }
	if tcp.RST { flags = append(flags, "RST") }
	if tcp.PSH { flags = append(flags, "PSH") }
	if tcp.ACK { flags = append(flags, "ACK") }
	if tcp.URG { flags = append(flags, "URG") }
	return strings.Join(flags, "|")
}

// ListDevices returns a list of available network interfaces
func ListDevices() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}