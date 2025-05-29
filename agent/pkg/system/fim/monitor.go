package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// FileState represents the state of a monitored file
type FileState struct {
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	Mode         os.FileMode `json:"mode"`
	ModTime      time.Time `json:"mod_time"`
	Hash         string    `json:"hash"`
	LastChecked  time.Time `json:"last_checked"`
}

// Event represents a file change event
type Event struct {
	Path      string    `json:"path"`
	Type      string    `json:"type"` // Created, Modified, Deleted, PermissionChanged
	OldState  *FileState `json:"old_state,omitempty"`
	NewState  *FileState `json:"new_state,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Config holds FIM configuration
type Config struct {
	Paths           []string        // Paths to monitor
	ExcludePaths    []string        // Paths to exclude
	HashAlgorithm   string         // Currently only supports SHA256
	ScanInterval    time.Duration   // Interval for full scans
	EnableRealtime  bool           // Enable real-time monitoring using fsnotify
}

// Monitor handles file integrity monitoring
type Monitor struct {
	config       Config
	states       map[string]*FileState
	watcher      *fsnotify.Watcher
	eventChan    chan<- Event
	excludeMap   map[string]bool
	mu           sync.RWMutex
	stopChan     chan struct{}
	lastEvents   map[string]time.Time // Track last event time per file
	eventMu      sync.Mutex          // Separate mutex for event tracking
}

// NewMonitor creates a new FIM monitor
func NewMonitor(config Config, eventChan chan<- Event) (*Monitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	excludeMap := make(map[string]bool)
	for _, path := range config.ExcludePaths {
		excludeMap[path] = true
	}

	m := &Monitor{
		config:     config,
		states:     make(map[string]*FileState),
		watcher:    watcher,
		eventChan:  eventChan,
		excludeMap: excludeMap,
		stopChan:   make(chan struct{}),
		lastEvents: make(map[string]time.Time),
	}

	return m, nil
}

// Start begins monitoring files
func (m *Monitor) Start() error {
	// Initialize baseline
	if err := m.scanAll(); err != nil {
		return err
	}

	// Start real-time monitoring if enabled
	if m.config.EnableRealtime {
		for _, path := range m.config.Paths {
			if err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return m.watcher.Add(path)
				}
				return nil
			}); err != nil {
				return err
			}
		}

		go m.watcherLoop()
	}

	// Start periodic scanning
	go m.scanLoop()

	return nil
}

// Stop stops monitoring
func (m *Monitor) Stop() {
	close(m.stopChan)
	if m.watcher != nil {
		m.watcher.Close()
	}
}

// calculateFileHash generates SHA256 hash of a file
func (m *Monitor) calculateFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// getFileState gets current state of a file
func (m *Monitor) getFileState(path string) (*FileState, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	hash := ""
	if !info.IsDir() {
		hash, err = m.calculateFileHash(path)
		if err != nil {
			return nil, err
		}
	}

	return &FileState{
		Path:        path,
		Size:        info.Size(),
		Mode:        info.Mode(),
		ModTime:     info.ModTime(),
		Hash:        hash,
		LastChecked: time.Now(),
	}, nil
}

// scanAll performs a full scan of monitored paths
func (m *Monitor) scanAll() error {
	newStates := make(map[string]*FileState)

	for _, path := range m.config.Paths {
		err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip excluded paths
			if m.excludeMap[path] {
				return filepath.SkipDir
			}

			state, err := m.getFileState(path)
			if err != nil {
				return err
			}

			m.mu.Lock()
			oldState, exists := m.states[path]
			m.mu.Unlock()

			if exists {
				if !m.statesEqual(oldState, state) {
					m.eventChan <- Event{
						Path:      path,
						Type:      "Modified",
						OldState:  oldState,
						NewState:  state,
						Timestamp: time.Now(),
					}
				}
			} else {
				m.eventChan <- Event{
					Path:      path,
					Type:      "Created",
					NewState:  state,
					Timestamp: time.Now(),
				}
			}

			newStates[path] = state
			return nil
		})

		if err != nil {
			return err
		}
	}

	// Check for deleted files
	m.mu.Lock()
	for path, oldState := range m.states {
		if _, exists := newStates[path]; !exists {
			m.eventChan <- Event{
				Path:      path,
				Type:      "Deleted",
				OldState:  oldState,
				Timestamp: time.Now(),
			}
		}
	}
	m.states = newStates
	m.mu.Unlock()

	return nil
}

// scanLoop performs periodic full scans
func (m *Monitor) scanLoop() {
	ticker := time.NewTicker(m.config.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			if err := m.scanAll(); err != nil {
				// Log error but continue monitoring
				continue
			}
		}
	}
}

// watcherLoop handles real-time file system events
func (m *Monitor) watcherLoop() {
	for {
		select {
		case <-m.stopChan:
			return
		case event := <-m.watcher.Events:
			// Skip excluded paths
			if m.excludeMap[event.Name] {
				continue
			}

			m.handleFsEvent(event)
		case err := <-m.watcher.Errors:
			// Log error but continue monitoring
			_ = err
		}
	}
}

// shouldProcessEvent checks if enough time has passed since the last event
func (m *Monitor) shouldProcessEvent(path string, eventType string) bool {
	m.eventMu.Lock()
	defer m.eventMu.Unlock()

	key := path + ":" + eventType
	now := time.Now()
	if lastTime, exists := m.lastEvents[key]; exists {
		if now.Sub(lastTime) < 100*time.Millisecond {
			return false
		}
	}
	m.lastEvents[key] = now
	return true
}

// handleFsEvent processes a filesystem event
func (m *Monitor) handleFsEvent(event fsnotify.Event) {
	switch {
	case event.Op&fsnotify.Create == fsnotify.Create:
		if !m.shouldProcessEvent(event.Name, "Created") {
			return
		}
		if state, err := m.getFileState(event.Name); err == nil {
			m.mu.Lock()
			if _, exists := m.states[event.Name]; !exists {
				m.states[event.Name] = state
				m.mu.Unlock()
				m.eventChan <- Event{
					Path:      event.Name,
					Type:      "Created",
					NewState:  state,
					Timestamp: time.Now(),
				}
			} else {
				m.mu.Unlock()
			}
		}

	case event.Op&fsnotify.Write == fsnotify.Write:
		if !m.shouldProcessEvent(event.Name, "Modified") {
			return
		}
		if state, err := m.getFileState(event.Name); err == nil {
			m.mu.Lock()
			oldState := m.states[event.Name]
			if !m.statesEqual(oldState, state) {
				m.states[event.Name] = state
				m.mu.Unlock()
				m.eventChan <- Event{
					Path:      event.Name,
					Type:      "Modified",
					OldState:  oldState,
					NewState:  state,
					Timestamp: time.Now(),
				}
			} else {
				m.mu.Unlock()
			}
		}

	case event.Op&fsnotify.Remove == fsnotify.Remove:
		if !m.shouldProcessEvent(event.Name, "Deleted") {
			return
		}
		m.mu.Lock()
		if oldState, exists := m.states[event.Name]; exists {
			delete(m.states, event.Name)
			m.mu.Unlock()
			// Send delete event after a small delay to ensure no recreate events are pending
			time.AfterFunc(50*time.Millisecond, func() {
				if _, err := os.Stat(event.Name); os.IsNotExist(err) {
					m.eventChan <- Event{
						Path:      event.Name,
						Type:      "Deleted",
						OldState:  oldState,
						Timestamp: time.Now(),
					}
				}
			})
		} else {
			m.mu.Unlock()
		}

	case event.Op&fsnotify.Chmod == fsnotify.Chmod:
		if !m.shouldProcessEvent(event.Name, "PermissionChanged") {
			return
		}
		if state, err := m.getFileState(event.Name); err == nil {
			m.mu.Lock()
			oldState := m.states[event.Name]
			if oldState != nil && oldState.Mode != state.Mode {
				m.states[event.Name] = state
				m.mu.Unlock()
				m.eventChan <- Event{
					Path:      event.Name,
					Type:      "PermissionChanged",
					OldState:  oldState,
					NewState:  state,
					Timestamp: time.Now(),
				}
			} else {
				m.mu.Unlock()
			}
		}
	}
}

// statesEqual compares two file states
func (m *Monitor) statesEqual(a, b *FileState) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Size == b.Size &&
		a.Mode == b.Mode &&
		a.ModTime.Equal(b.ModTime) &&
		a.Hash == b.Hash
}