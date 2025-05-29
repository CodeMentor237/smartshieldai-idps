package network

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/oschwald/maxminddb-golang"
)

// CaptureConfig holds configuration for packet capture
type CaptureConfig struct {
	DeviceName     string
	SnapLen        int32
	BPFFilter      string
	BufferSize     int
	ChannelSize    int
	CollectPayload bool
	GeoIPDBPath    string
	ExcludeIPs     []string
	ExcludePorts   []uint16
}

// GeoIPData contains geolocation information
type GeoIPData struct {
	Country     string  `json:"country,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
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
	SourceGeo      *GeoIPData      `json:"source_geo,omitempty"`
	DestinationGeo *GeoIPData      `json:"destination_geo,omitempty"`
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
	geoIPDB     *maxminddb.Reader
	excludeIPs   map[string]bool
	excludePorts map[uint16]bool
}

// CaptureStats holds packet capture statistics
type CaptureStats struct {
	PacketsReceived  uint64
	PacketsDropped   uint64
	PacketsFiltered  uint64
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
		GeoIPDBPath:    "/usr/share/GeoIP/GeoLite2-City.mmdb",
		ExcludeIPs:     []string{"127.0.0.1", "::1"},
		ExcludePorts:   []uint16{53, 123}, // Exclude DNS and NTP by default
	}
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

	// Initialize exclusion maps
	excludeIPs := make(map[string]bool)
	for _, ip := range config.ExcludeIPs {
		excludeIPs[ip] = true
	}

	excludePorts := make(map[uint16]bool)
	for _, port := range config.ExcludePorts {
		excludePorts[port] = true
	}

	return &Capture{
		handle:       handle,
		config:       config,
		excludeIPs:   excludeIPs,
		excludePorts: excludePorts,
	}, nil
}

// lookupGeoIP looks up geolocation data for an IP address
func (c *Capture) lookupGeoIP(ip string) *GeoIPData {
	if c.geoIPDB == nil {
		return nil
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil
	}

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Location struct {
			Latitude  float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}

	err := c.geoIPDB.Lookup(parsedIP, &record)
	if err != nil {
		return nil
	}

	return &GeoIPData{
		Country:     record.Country.ISOCode,
		City:        record.City.Names["en"],
		Latitude:    record.Location.Latitude,
		Longitude:   record.Location.Longitude,
	}
}

// shouldFilterPacket determines if a packet should be filtered out
func (c *Capture) shouldFilterPacket(srcIP, dstIP string, srcPort, dstPort uint16) bool {
	// Check excluded IPs
	if c.excludeIPs[srcIP] || c.excludeIPs[dstIP] {
		return true
	}

	// Check excluded ports
	if c.excludePorts[srcPort] || c.excludePorts[dstPort] {
		return true
	}

	return false
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

			var srcPort, dstPort uint16

			// Extract network layer information
			if networkLayer := packet.NetworkLayer(); networkLayer != nil {
				src := networkLayer.NetworkFlow().Src().String()
				dst := networkLayer.NetworkFlow().Dst().String()
				packetData.Source = src
				packetData.Destination = dst
				packetData.Protocol = networkLayer.LayerType().String()

				// Add GeoIP data
				packetData.SourceGeo = c.lookupGeoIP(src)
				packetData.DestinationGeo = c.lookupGeoIP(dst)
			}

			// Extract transport layer information
			if transportLayer := packet.TransportLayer(); transportLayer != nil {
				switch t := transportLayer.(type) {
				case *layers.TCP:
					srcPort = uint16(t.SrcPort)
					dstPort = uint16(t.DstPort)
					packetData.PacketType = "TCP"
					packetData.TCPInfo = &TCPMetadata{
						SrcPort:    srcPort,
						DstPort:    dstPort,
						Seq:        t.Seq,
						Ack:        t.Ack,
						WindowSize: t.Window,
						Flags:      getTCPFlags(t),
					}
				case *layers.UDP:
					srcPort = uint16(t.SrcPort)
					dstPort = uint16(t.DstPort)
					packetData.PacketType = "UDP"
					packetData.UDPInfo = &UDPMetadata{
						SrcPort: srcPort,
						DstPort: dstPort,
						Length:  uint16(len(t.Payload)),
					}
				}

				// Check if packet should be filtered
				if c.shouldFilterPacket(packetData.Source, packetData.Destination, srcPort, dstPort) {
					c.stats.PacketsFiltered++
					continue
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

// initGeoIP initializes the GeoIP database
func (c *Capture) initGeoIP() error {
	if c.config.GeoIPDBPath == "" {
		return nil // GeoIP is optional
	}

	db, err := maxminddb.Open(c.config.GeoIPDBPath)
	if err != nil {
		return fmt.Errorf("error opening GeoIP database: %v", err)
	}

	c.geoIPDB = db
	return nil
}

// Close releases resources
func (c *Capture) Close() {
	if c.handle != nil {
		c.handle.Close()
	}
	if c.geoIPDB != nil {
		c.geoIPDB.Close()
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