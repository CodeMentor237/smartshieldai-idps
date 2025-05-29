package testdata

import (
	"github.com/google/gopacket/layers"
)

// MockHandle simulates a pcap handle for testing
type MockHandle struct {
	closed bool
}

func (h *MockHandle) Close()                   { h.closed = true }
func (h *MockHandle) Stats() (*Stats, error)   { return &Stats{}, nil }
func (h *MockHandle) LinkType() layers.LinkType { return layers.LinkTypeEthernet }

// Stats represents mock packet statistics
type Stats struct {
	PacketsReceived, PacketsDropped uint32
}

// NewMockHandle creates a new mock packet capture handle
func NewMockHandle() *MockHandle {
	return &MockHandle{}
}