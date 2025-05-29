package network

import (
	"testing"
	"time"

	"github.com/smartshieldai-idps/agent/pkg/network/testdata"
)

type testCapture struct {
	*Capture
	mockHandle *testdata.MockHandle
}

func newTestCapture(config CaptureConfig) (*testCapture, error) {
	mockHandle := testdata.NewMockHandle()
	c := &Capture{
		config:       config,
		excludeIPs:   make(map[string]bool),
		excludePorts: make(map[uint16]bool),
	}

	// Initialize exclusion maps
	for _, ip := range config.ExcludeIPs {
		c.excludeIPs[ip] = true
	}
	for _, port := range config.ExcludePorts {
		c.excludePorts[port] = true
	}

	return &testCapture{
		Capture:    c,
		mockHandle: mockHandle,
	}, nil
}

func TestPacketFiltering(t *testing.T) {
	config := CaptureConfig{
		ExcludeIPs:   []string{"192.168.1.1", "10.0.0.1"},
		ExcludePorts: []uint16{53, 123},
	}

	capture, err := newTestCapture(config)
	if err != nil {
		t.Fatalf("Failed to create test capture: %v", err)
	}

	tests := []struct {
		name     string
		srcIP    string
		dstIP    string
		srcPort  uint16
		dstPort  uint16
		expected bool
	}{
		{"ExcludedSourceIP", "192.168.1.1", "8.8.8.8", 1234, 80, true},
		{"ExcludedDestIP", "8.8.8.8", "10.0.0.1", 1234, 80, true},
		{"ExcludedSourcePort", "8.8.8.8", "1.1.1.1", 53, 80, true},
		{"ExcludedDestPort", "8.8.8.8", "1.1.1.1", 1234, 123, true},
		{"AllowedTraffic", "8.8.8.8", "1.1.1.1", 1234, 80, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := capture.shouldFilterPacket(tt.srcIP, tt.dstIP, tt.srcPort, tt.dstPort)
			if result != tt.expected {
				t.Errorf("shouldFilterPacket() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGeoIPLookup(t *testing.T) {
	// Create mock GeoIP database
	dbPath, err := testdata.CreateMockGeoIPDB()
	if err != nil {
		t.Fatalf("Failed to create mock GeoIP database: %v", err)
	}
	defer testdata.CleanupMockGeoIPDB(dbPath)

	config := CaptureConfig{
		GeoIPDBPath: dbPath,
	}

	capture, err := newTestCapture(config)
	if err != nil {
		t.Fatalf("Failed to create test capture: %v", err)
	}

	// Initialize GeoIP database
	if err := capture.initGeoIP(); err != nil {
		t.Fatalf("Failed to initialize GeoIP: %v", err)
	}

	tests := []struct {
		name        string
		ip          string
		wantNil     bool
		wantCountry string
	}{
		{"GoogleDNS", "8.8.8.8", false, "US"},
		{"LocalHost", "127.0.0.1", true, ""},
		{"InvalidIP", "invalid", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := capture.lookupGeoIP(tt.ip)
			if (result == nil) != tt.wantNil {
				t.Errorf("lookupGeoIP() nil check failed, got = %v, want nil = %v", result, tt.wantNil)
				return
			}
			if !tt.wantNil && result.Country != tt.wantCountry {
				t.Errorf("lookupGeoIP() country = %v, want %v", result.Country, tt.wantCountry)
			}
		})
	}
}

func TestPacketDataEnrichment(t *testing.T) {
	// Create mock GeoIP database
	dbPath, err := testdata.CreateMockGeoIPDB()
	if err != nil {
		t.Fatalf("Failed to create mock GeoIP database: %v", err)
	}
	defer testdata.CleanupMockGeoIPDB(dbPath)

	config := CaptureConfig{
		GeoIPDBPath: dbPath,
	}

	capture, err := newTestCapture(config)
	if err != nil {
		t.Fatalf("Failed to create test capture: %v", err)
	}

	// Initialize GeoIP database
	if err := capture.initGeoIP(); err != nil {
		t.Fatalf("Failed to initialize GeoIP: %v", err)
	}

	testPacket := PacketData{
		Timestamp:   time.Now(),
		Source:      "8.8.8.8",
		Destination: "1.1.1.1",
		Protocol:    "TCP",
		Length:      100,
		PacketType:  "TCP",
		TCPInfo: &TCPMetadata{
			SrcPort:    53,
			DstPort:    80,
			WindowSize: 1024,
			Flags:      "SYN",
		},
	}

	// Add GeoIP data
	testPacket.SourceGeo = capture.lookupGeoIP(testPacket.Source)
	testPacket.DestinationGeo = capture.lookupGeoIP(testPacket.Destination)

	// Verify GeoIP enrichment
	if testPacket.SourceGeo == nil {
		t.Error("Expected non-nil source GeoIP data")
	} else {
		if testPacket.SourceGeo.Country != "US" {
			t.Errorf("Expected source country US, got %s", testPacket.SourceGeo.Country)
		}
	}
}