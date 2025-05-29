package network

import (
	"context"
	"testing"
	"time"

	"github.com/smartshieldai-idps/agent/config"
)

func TestNewCapture(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.NetworkConfig
		wantErr bool
	}{
		{
			name: "ValidConfig",
			config: &config.NetworkConfig{
				Interface: "eth0",
				BPFFilter: "",
			},
			wantErr: false,
		},
		{
			name: "EmptyInterface",
			config: &config.NetworkConfig{
				Interface: "",
				BPFFilter: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCapture(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCapture() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCaptureStart(t *testing.T) {
	config := &config.NetworkConfig{
		Interface: "eth0",
		BPFFilter: "",
	}

	capture, err := NewCapture(config)
	if err != nil {
		t.Fatalf("Failed to create capture: %v", err)
	}

	packetChan := make(chan []byte, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = capture.Start(ctx, packetChan)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}

	// Wait for a few packets
	time.Sleep(100 * time.Millisecond)

	// Check stats
	stats := capture.GetStats()
	if stats.PacketsReceived == 0 {
		t.Error("Expected packets to be received")
	}
}

func TestCaptureStop(t *testing.T) {
	config := &config.NetworkConfig{
		Interface: "eth0",
		BPFFilter: "",
	}

	capture, err := NewCapture(config)
	if err != nil {
		t.Fatalf("Failed to create capture: %v", err)
	}

	packetChan := make(chan []byte, 10)
	ctx, cancel := context.WithCancel(context.Background())

	err = capture.Start(ctx, packetChan)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}

	// Stop capture
	capture.Stop()
	cancel()

	// Wait a bit to ensure everything is stopped
	time.Sleep(100 * time.Millisecond)

	// Check that no more packets are being received
	initialStats := capture.GetStats()
	time.Sleep(100 * time.Millisecond)
	finalStats := capture.GetStats()

	if finalStats.PacketsReceived != initialStats.PacketsReceived {
		t.Error("Expected no more packets to be received after stop")
	}
}