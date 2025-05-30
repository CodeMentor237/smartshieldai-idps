package network

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/oschwald/geoip2-golang"
	"github.com/smartshieldai-idps/agent/config"
)

// GeoData represents geographical information for an IP address
type GeoData struct {
	Country     string `json:"country,omitempty"`
	City        string `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	ASN         uint   `json:"asn,omitempty"`
	ASName      string `json:"as_name,omitempty"`
}

// PacketData represents a captured network packet
type PacketData struct {
	Timestamp    time.Time `json:"timestamp"`
	SourceIP     string    `json:"source_ip"`
	DestIP       string    `json:"dest_ip"`
	Protocol     string    `json:"protocol"`
	SourcePort   uint16    `json:"source_port"`
	DestPort     uint16    `json:"dest_port"`
	Length       int       `json:"length"`
	Payload      string    `json:"payload,omitempty"` // Base64 encoded
	TCPFlags     string    `json:"tcp_flags,omitempty"`
	ICMPType     uint8     `json:"icmp_type,omitempty"`
	ICMPCode     uint8     `json:"icmp_code,omitempty"`
	SourceGeo    *GeoData  `json:"source_geo,omitempty"`
	DestGeo      *GeoData  `json:"dest_geo,omitempty"`
}

// Capture represents a network packet capture
type Capture struct {
	config *config.NetworkConfig
	stats  *Stats
	geoDB  *geoip2.Reader
}

// Stats represents capture statistics
type Stats struct {
	PacketsReceived uint64
	PacketsDropped  uint64
	PacketsFiltered uint64
	LastUpdate      time.Time
}

// NewCapture creates a new network capture
func NewCapture(cfg *config.NetworkConfig) (*Capture, error) {
	if len(cfg.Interfaces) == 0 {
		return nil, fmt.Errorf("at least one network interface is required")
	}

	// Initialize GeoIP database
	var geoDB *geoip2.Reader
	if cfg.GeoIPDBPath != "" {
		db, err := geoip2.Open(cfg.GeoIPDBPath)
		if err != nil {
			log.Printf("Warning: Failed to open GeoIP database at %s: %v. GeoIP enrichment will be disabled.", cfg.GeoIPDBPath, err)
			geoDB = nil
		} else {
			geoDB = db
			log.Printf("Successfully loaded GeoIP database from %s", cfg.GeoIPDBPath)
		}
	} else {
		log.Println("GeoIPDBPath not configured. GeoIP enrichment will be disabled.")
		geoDB = nil
	}

	return &Capture{
		config: cfg,
		stats: &Stats{
			LastUpdate: time.Now(),
		},
		geoDB: geoDB,
	}, nil
}

// Start begins packet capture
func (c *Capture) Start(ctx context.Context, packetChan chan<- []byte) error {
	// Get the first interface from the list
	if len(c.config.Interfaces) == 0 {
		return fmt.Errorf("no network interfaces configured")
	}
	interfaceName := c.config.Interfaces[0]

	// Log system information
	log.Printf("System information:")
	log.Printf("  OS: %s", runtime.GOOS)
	log.Printf("  Architecture: %s", runtime.GOARCH)
	log.Printf("  Running as root: %v", os.Geteuid() == 0)

	// Log available interfaces
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("failed to find network interfaces: %v", err)
	}

	// Find the best interface to use
	var bestInterface string
	var bestScore int
	for _, device := range devices {
		score := 0
		// Prefer interfaces with IPv4 addresses
		for _, addr := range device.Addresses {
			if addr.IP.To4() != nil {
				score += 2
			}
		}
		// Prefer non-loopback interfaces
		if !strings.HasPrefix(device.Name, "lo") {
			score += 1
		}
		// Prefer non-tunnel interfaces
		if !strings.HasPrefix(device.Name, "utun") {
			score += 1
		}
		// Prefer en0 on macOS
		if runtime.GOOS == "darwin" && device.Name == "en0" {
			score += 3
		}
		// Prefer eth0 on Linux
		if runtime.GOOS == "linux" && device.Name == "eth0" {
			score += 3
		}
		if score > bestScore {
			bestScore = score
			bestInterface = device.Name
		}
		log.Printf("  - %s: %s (score: %d)", device.Name, device.Description, score)
		for _, addr := range device.Addresses {
			log.Printf("    IP: %v", addr.IP)
		}
	}

	// If no interface was specified, use the best one found
	if interfaceName == "" {
		interfaceName = bestInterface
		log.Printf("No interface specified, using best available: %s", interfaceName)
	} else if interfaceName == "eth0" && runtime.GOOS == "darwin" {
		// If eth0 was specified on macOS, use en0 instead
		interfaceName = "en0"
		log.Printf("Interface eth0 specified but not available on macOS, using en0 instead")
	}

	// Verify interface exists
	var found bool
	for _, device := range devices {
		if device.Name == interfaceName {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("interface %s not found", interfaceName)
	}

	// Start packet capture
	log.Printf("Starting packet capture on interface: %s", interfaceName)
	handle, err := c.openInterface(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", interfaceName, err)
	}
	defer handle.Close()

	// Set capture filter if specified
	if c.config.CaptureFilter != "" {
		log.Printf("Setting capture filter: %s", c.config.CaptureFilter)
		if err := handle.SetBPFFilter(c.config.CaptureFilter); err != nil {
			return fmt.Errorf("failed to set capture filter: %v", err)
		}
	} else {
		// Platform-specific default filters
		var defaultFilter string
		switch runtime.GOOS {
		case "darwin":
			defaultFilter = "ip or ip6 or tcp or udp or icmp or icmp6"
		case "linux":
			defaultFilter = "ip or ip6"
		default:
			defaultFilter = "ip or ip6"
		}
		log.Printf("Setting default capture filter for %s: %s", runtime.GOOS, defaultFilter)
		if err := handle.SetBPFFilter(defaultFilter); err != nil {
			return fmt.Errorf("failed to set default capture filter: %v", err)
		}
	}

	// Create packet source with platform-specific settings
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.DecodeOptions.Lazy = true
	source.DecodeOptions.NoCopy = true

	// Log capture settings
	log.Printf("Capture settings:")
	log.Printf("  Interface: %s", interfaceName)
	log.Printf("  Link type: %v", handle.LinkType())
	log.Printf("  Filter: %s", c.config.CaptureFilter)
	log.Printf("  Max packet size: %d", c.config.MaxPacketSize)

	// Start capture loop
	go c.captureLoop(ctx, source, packetChan)

	// Start stats reporting with more frequent updates
	go c.reportStats(ctx)

	// Verify capture is working by waiting for a packet
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		if c.stats.PacketsReceived == 0 {
			return fmt.Errorf("no packets received after 5 seconds")
		}
		log.Printf("Successfully captured %d packets", c.stats.PacketsReceived)
	}

	return nil
}

// captureLoop processes captured packets
func (c *Capture) captureLoop(ctx context.Context, source *gopacket.PacketSource, packetChan chan<- []byte) {
	packets := source.Packets()
	for {
		select {
		case <-ctx.Done():
			log.Printf("Capture loop stopped")
			return
		case packet, ok := <-packets:
			if !ok {
				// If the channel is closed, try to get a new one
				packets = source.Packets()
				continue
			}
			if packet == nil {
				continue
			}

			// Skip packets that are too small or too large
			if packet.Metadata().Length < 60 || packet.Metadata().Length > c.config.MaxPacketSize {
				c.stats.PacketsFiltered++
				continue
			}

			// Skip packets without network layer
			if packet.NetworkLayer() == nil {
				c.stats.PacketsFiltered++
				continue
			}

			c.stats.PacketsReceived++

			// Process packet
			packetData := c.processPacket(packet)
			if packetData == nil {
				c.stats.PacketsFiltered++
				continue
			}

			// Skip packets with empty payloads
			if packetData.Length == 0 {
				c.stats.PacketsFiltered++
				continue
			}

			// Marshal packet data to JSON
			data, err := json.Marshal(packetData)
			if err != nil {
				log.Printf("Error marshaling packet data: %v", err)
				c.stats.PacketsDropped++
				continue
			}

			// Send to channel
			select {
			case packetChan <- data:
			default:
				c.stats.PacketsDropped++
			}
		}
	}
}

// reportStats periodically reports capture statistics
func (c *Capture) reportStats(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second) // Changed from 30s to 5s for more frequent updates
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := c.GetStats()
			log.Printf("Network stats: Received=%d, Dropped=%d, Filtered=%d",
				stats.PacketsReceived,
				stats.PacketsDropped,
				stats.PacketsFiltered)
		}
	}
}

// getGeoData retrieves geographical information for an IP address
func (c *Capture) getGeoData(ip string) *GeoData {
	if c.geoDB == nil {
		return nil
	}

	netIP := net.ParseIP(ip)
	if netIP == nil {
		return nil
	}

	record, err := c.geoDB.City(netIP)
	if err != nil {
		return nil
	}

	return &GeoData{
		Country:   record.Country.Names["en"],
		City:      record.City.Names["en"],
		Latitude:  record.Location.Latitude,
		Longitude: record.Location.Longitude,
	}
}

// processPacket extracts relevant information from a packet
func (c *Capture) processPacket(packet gopacket.Packet) *PacketData {
	if packet == nil {
		return nil
	}

	// Check packet length
	if packet.Metadata().Length > c.config.MaxPacketSize {
		return nil
	}

	// Extract network layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return nil
	}

	// Create packet data
	packetData := &PacketData{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
	}

	// Process IP layer
	switch ipLayer := networkLayer.(type) {
	case *layers.IPv4:
		packetData.SourceIP = ipLayer.SrcIP.String()
		packetData.DestIP = ipLayer.DstIP.String()
		packetData.Protocol = ipLayer.Protocol.String()
		
		// Add GeoIP data
		packetData.SourceGeo = c.getGeoData(packetData.SourceIP)
		packetData.DestGeo = c.getGeoData(packetData.DestIP)
		
	case *layers.IPv6:
		packetData.SourceIP = ipLayer.SrcIP.String()
		packetData.DestIP = ipLayer.DstIP.String()
		packetData.Protocol = ipLayer.NextHeader.String()
		
		// Add GeoIP data for IPv6
		packetData.SourceGeo = c.getGeoData(packetData.SourceIP)
		packetData.DestGeo = c.getGeoData(packetData.DestIP)
		
	default:
		return nil
	}

	// Process transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer != nil {
		switch tcpLayer := transportLayer.(type) {
		case *layers.TCP:
			packetData.SourcePort = uint16(tcpLayer.SrcPort)
			packetData.DestPort = uint16(tcpLayer.DstPort)
			
			// Build TCP flags string
			var flags []string
			if tcpLayer.FIN { flags = append(flags, "FIN") }
			if tcpLayer.SYN { flags = append(flags, "SYN") }
			if tcpLayer.RST { flags = append(flags, "RST") }
			if tcpLayer.PSH { flags = append(flags, "PSH") }
			if tcpLayer.ACK { flags = append(flags, "ACK") }
			if tcpLayer.URG { flags = append(flags, "URG") }
			packetData.TCPFlags = strings.Join(flags, ",")
			
			// Encode payload if present
			if len(tcpLayer.Payload) > 0 {
				packetData.Payload = base64.StdEncoding.EncodeToString(tcpLayer.Payload)
			}
		case *layers.UDP:
			packetData.SourcePort = uint16(tcpLayer.SrcPort)
			packetData.DestPort = uint16(tcpLayer.DstPort)
			
			// Encode payload if present
			if len(tcpLayer.Payload) > 0 {
				packetData.Payload = base64.StdEncoding.EncodeToString(tcpLayer.Payload)
			}
		}
	}

	// Process ICMP layer separately since it's not a transport layer
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		if icmp, ok := icmpLayer.(*layers.ICMPv4); ok {
			packetData.ICMPType = uint8(icmp.TypeCode.Type())
			packetData.ICMPCode = uint8(icmp.TypeCode.Code())
		}
	}
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		if icmp, ok := icmpLayer.(*layers.ICMPv6); ok {
			packetData.ICMPType = uint8(icmp.TypeCode.Type())
			packetData.ICMPCode = uint8(icmp.TypeCode.Code())
		}
	}

	return packetData
}

// Stop stops packet capture
func (c *Capture) Stop() {
	if len(c.config.Interfaces) > 0 {
		log.Printf("Stopping packet capture on interface: %s", c.config.Interfaces[0])
	}
	if c.geoDB != nil {
		c.geoDB.Close()
	}
}

// GetStats returns capture statistics
func (c *Capture) GetStats() *Stats {
	return c.stats
}

// openInterface opens a network interface for packet capture
func (c *Capture) openInterface(interfaceName string) (*pcap.Handle, error) {
	// Platform-specific settings
	var snapshotLen int32
	var timeout time.Duration
	var promisc bool

	switch runtime.GOOS {
	case "darwin":
		snapshotLen = 65535 // macOS can handle larger packets
		timeout = pcap.BlockForever
		promisc = false // macOS often doesn't need promiscuous mode
	case "linux":
		snapshotLen = 65535
		timeout = pcap.BlockForever
		promisc = true
	default:
		snapshotLen = 65535
		timeout = pcap.BlockForever
		promisc = true
	}

	log.Printf("Attempting to open interface %s with settings:", interfaceName)
	log.Printf("  OS: %s", runtime.GOOS)
	log.Printf("  Snapshot length: %d", snapshotLen)
	log.Printf("  Timeout: %v", timeout)
	log.Printf("  Promiscuous mode: %v", promisc)

	// Try to open interface with platform-specific settings
	handle, err := pcap.OpenLive(interfaceName, snapshotLen, promisc, timeout)
	if err != nil {
		log.Printf("Failed to open interface with initial settings: %v", err)
		
		// Try alternative settings
		if runtime.GOOS == "darwin" {
			log.Printf("Trying alternative settings for macOS...")
			// Try each BPF device with different settings
			for i := 0; i < 4; i++ {
				log.Printf("Attempt %d to open interface...", i+1)
				// Try without promiscuous mode
				handle, err = pcap.OpenLive(interfaceName, snapshotLen, false, timeout)
				if err == nil {
					log.Printf("Successfully opened interface on attempt %d", i+1)
					break
				}
				log.Printf("Attempt %d failed: %v", i+1, err)
				time.Sleep(100 * time.Millisecond)
			}
		} else {
			// For other platforms, try without promiscuous mode
			log.Printf("Trying without promiscuous mode...")
			handle, err = pcap.OpenLive(interfaceName, snapshotLen, false, timeout)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to open interface after all attempts: %v", err)
		}
	}

	// Log successful interface opening
	log.Printf("Successfully opened interface %s", interfaceName)
	log.Printf("Interface link type: %v", handle.LinkType())

	return handle, nil
}