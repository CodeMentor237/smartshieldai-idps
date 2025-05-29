package fim

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFIMMonitor(t *testing.T) {
	// Create temporary test directory
	testDir, err := ioutil.TempDir("", "fim-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create event channel with buffer
	eventChan := make(chan Event, 100)

	// Create FIM config with shorter scan interval for testing
	config := Config{
		Paths:          []string{testDir},
		ExcludePaths:   []string{},
		HashAlgorithm:  "sha256",
		ScanInterval:   500 * time.Millisecond,
		EnableRealtime: true,
	}

	// Create and start monitor
	monitor, err := NewMonitor(config, eventChan)
	if err != nil {
		t.Fatalf("Failed to create monitor: %v", err)
	}

	if err := monitor.Start(); err != nil {
		t.Fatalf("Failed to start monitor: %v", err)
	}
	defer monitor.Stop()

	// Wait for initial setup and clear any startup events
	time.Sleep(100 * time.Millisecond)
	for len(eventChan) > 0 {
		<-eventChan
	}

	// Helper function to wait for events
	waitForEvents := func() []Event {
		var events []Event
		timeout := time.After(1 * time.Second)
		for {
			select {
			case event := <-eventChan:
				// Only collect events for files we create
				if filepath.Dir(event.Path) == testDir {
					events = append(events, event)
				}
			case <-timeout:
				return events
			}
		}
	}

	// Test file creation
	testFile1 := filepath.Join(testDir, "test1.txt")
	if err := ioutil.WriteFile(testFile1, []byte("test content 1"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	createEvents := waitForEvents()
	if len(createEvents) != 1 || createEvents[0].Type != "Created" {
		t.Fatalf("Expected 1 Create event, got %d events", len(createEvents))
	}

	// Test file modification
	time.Sleep(200 * time.Millisecond) // Wait before modification
	if err := ioutil.WriteFile(testFile1, []byte("modified content"), 0644); err != nil {
		t.Fatalf("Failed to modify test file: %v", err)
	}

	modifyEvents := waitForEvents()
	modifyCount := 0
	for _, e := range modifyEvents {
		if e.Type == "Modified" {
			modifyCount++
		}
	}
	if modifyCount != 1 {
		t.Errorf("Expected 1 Modify event, got %d", modifyCount)
	}

	// Test permission change
	time.Sleep(200 * time.Millisecond) // Wait before permission change
	if err := os.Chmod(testFile1, 0600); err != nil {
		t.Fatalf("Failed to change file permissions: %v", err)
	}

	permEvents := waitForEvents()
	permCount := 0
	for _, e := range permEvents {
		if e.Type == "PermissionChanged" {
			permCount++
		}
	}
	if permCount != 1 {
		t.Errorf("Expected 1 PermissionChanged event, got %d", permCount)
	}

	// Test file deletion
	time.Sleep(200 * time.Millisecond) // Wait before deletion
	if err := os.Remove(testFile1); err != nil {
		t.Fatalf("Failed to remove test file: %v", err)
	}

	deleteEvents := waitForEvents()
	deleteCount := 0
	for _, e := range deleteEvents {
		if e.Type == "Deleted" {
			deleteCount++
		}
	}
	if deleteCount != 1 {
		t.Errorf("Expected 1 Delete event, got %d", deleteCount)
	}

	// Final verification of event details
	verifyState := func(state *FileState) {
		if state == nil {
			t.Error("File state should not be nil")
			return
		}
		if state.Path == "" {
			t.Error("File path should not be empty")
		}
		if state.Hash == "" {
			t.Error("File hash should not be empty")
		}
		if state.LastChecked.IsZero() {
			t.Error("LastChecked should not be zero")
		}
	}

	// Verify all collected events
	for _, events := range [][]Event{createEvents, modifyEvents, permEvents, deleteEvents} {
		for _, event := range events {
			if event.Timestamp.IsZero() {
				t.Error("Event timestamp should not be zero")
			}
			switch event.Type {
			case "Created", "Modified":
				verifyState(event.NewState)
			case "Deleted":
				verifyState(event.OldState)
			case "PermissionChanged":
				verifyState(event.OldState)
				verifyState(event.NewState)
				if event.OldState.Mode == event.NewState.Mode {
					t.Error("File modes should differ in PermissionChanged event")
				}
			}
		}
	}
}