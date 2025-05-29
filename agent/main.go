package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/smartshieldai-idps/agent/pkg/network"
	"github.com/smartshieldai-idps/agent/pkg/system"
)

// Global configuration
const (
	maxPacketQueueSize = 10000
	maxLogQueueSize    = 10000
	statInterval       = 30 * time.Second
)

func main() {
	log.Println("Starting SmartShield AI IDPS Agent...")

	// Create buffered channels for data collection
	packetChan := make(chan network.PacketData, maxPacketQueueSize)
	logsChan := make(chan system.LogData, maxLogQueueSize)

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize network capture
	devices, err := network.ListDevices()
	if err != nil {
		log.Fatalf("Error listing network interfaces: %v", err)
	}

	// Start capture on each interface
	captures := make([]*network.Capture, 0)
	for _, device := range devices {
		// Skip interfaces without addresses
		if len(device.Addresses) == 0 {
			continue
		}

		config := network.DefaultConfig(device.Name)
		capture, err := network.NewCapture(config)
		if err != nil {
			log.Printf("Error creating capture for device %s: %v", device.Name, err)
			continue
		}

		captures = append(captures, capture)
		wg.Add(1)

		go func(dev string, cap *network.Capture) {
			defer wg.Done()
			if err := cap.Start(packetChan); err != nil {
				log.Printf("Error starting capture on device %s: %v", dev, err)
				return
			}
		}(device.Name, capture)

		log.Printf("Started packet capture on interface: %s", device.Name)
	}

	if len(captures) == 0 {
		log.Fatal("No network interfaces available for capture")
	}

	// Initialize system monitoring
	socketPath := getOsquerySocket()
	monitorConfig := system.DefaultConfig(socketPath)
	monitor, err := system.NewMonitor(monitorConfig)
	if err != nil {
		log.Printf("Error initializing system monitor: %v", err)
		log.Printf("System monitoring will be disabled - please ensure osqueryd is running")
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := monitor.Start(logsChan, ctx); err != nil {
				log.Printf("Error starting system monitor: %v", err)
				return
			}
		}()
		log.Println("Started system monitoring")

		// Log system information
		if sysInfo, err := monitor.GetSystemInfo(); err == nil {
			log.Printf("System Info: %v", sysInfo)
		}
	}

	// Start statistics reporting
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(statInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Report network statistics
				for _, capture := range captures {
					stats := capture.GetStats()
					log.Printf("Network stats: Received=%d, Dropped=%d, Filtered=%d",
						stats.PacketsReceived, stats.PacketsDropped, stats.PacketsFiltered)
				}

				// Report system monitoring statistics
				if monitor != nil {
					stats := monitor.GetStats()
					log.Printf("System monitor stats: Collected=%d, Dropped=%d, Errors=%d",
						stats.EventsCollected, stats.EventsDropped, stats.QueryErrors)
				}
			}
		}
	}()

	// Start packet processing goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for packet := range packetChan {
			// Skip processing if context is cancelled
			select {
			case <-ctx.Done():
				return
			default:
			}

			jsonData, err := json.Marshal(packet)
			if err != nil {
				log.Printf("Error marshaling packet data: %v", err)
				continue
			}
			log.Printf("Packet captured: %s", string(jsonData))
		}
	}()

	// Start system log processing goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for logData := range logsChan {
			// Skip processing if context is cancelled
			select {
			case <-ctx.Done():
				return
			default:
			}

			jsonData, err := json.Marshal(logData)
			if err != nil {
				log.Printf("Error marshaling log data: %v", err)
				continue
			}
			log.Printf("System log: %s", string(jsonData))
		}
	}()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutting down agent...")

	// Stop all captures and monitoring
	cancel()
	for _, capture := range captures {
		capture.Stop()
	}
	if monitor != nil {
		monitor.Stop()
	}

	// Close channels after all producers are stopped
	close(packetChan)
	close(logsChan)

	// Wait for all goroutines to finish
	wg.Wait()
	log.Println("Agent shutdown complete")
}

// getOsquerySocket returns the appropriate osquery socket path for the current OS
func getOsquerySocket() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\osquery.em` // Windows named pipe
	}
	// Unix domain socket path
	return filepath.Join("/var/osquery", "osquery.em")
}