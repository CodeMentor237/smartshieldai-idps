package prevention

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/smartshieldai-idps/backend/internal/detection/elasticsearch"
	"github.com/smartshieldai-idps/backend/internal/detection/ml"
)

// Handler implements prevention actions
type Handler struct {
	config    Config
	esLogger  *elasticsearch.Logger
	mu        sync.RWMutex
	actions   map[string]*Action // Track active prevention actions
	ctx       context.Context
	cancel    context.CancelFunc
}

// Action represents an active prevention action
type Action struct {
	Type       string    `json:"type"`
	Target     string    `json:"target"`
	StartTime  time.Time `json:"start_time"`
	ExpiryTime time.Time `json:"expiry_time"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
	RolledBack bool      `json:"rolled_back"`
	RollbackFn func() error
}

// NewHandler creates a new prevention handler
func NewHandler(config Config) *Handler {
	if err := config.Validate(); err != nil {
		log.Printf("Warning: invalid prevention config: %v, using defaults", err)
		config = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize Elasticsearch logger if not in dry-run mode
	var esLogger *elasticsearch.Logger
	if !config.DryRun {
		var err error
		esLogger, err = elasticsearch.NewLogger(
			config.ESAddrs,
			config.ESUser,
			config.ESPass,
			config.ESIndex,
		)
		if err != nil {
			log.Printf("Warning: failed to initialize Elasticsearch logger for prevention: %v", err)
		}
	}

	h := &Handler{
		config:   config,
		esLogger: esLogger,
		actions:  make(map[string]*Action),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Start cleanup goroutine
	go h.cleanupExpiredActions()

	return h
}

// Stop stops the prevention handler
func (h *Handler) Stop() {
	h.cancel()
	h.rollbackAllActions()
}

// TakeAction implements the PreventionHandler interface
func (h *Handler) TakeAction(action ml.PreventionAction) error {
	// Check confidence threshold
	if action.Confidence < h.config.AlertThreshold {
		return fmt.Errorf("confidence %.2f below threshold %.2f", action.Confidence, h.config.AlertThreshold)
	}

	// Log the action first
	if h.config.LogActions && h.esLogger != nil {
		if err := h.logAction(action); err != nil {
			log.Printf("Warning: failed to log prevention action: %v", err)
		}
	}

	// Check if target is whitelisted
	if h.isWhitelisted(action) {
		return fmt.Errorf("target %s is whitelisted", action.Target)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Determine action implementation
	var (
		err error
		fn  func() error // Rollback function
	)

	switch action.Type {
	case "block_ip":
		if !h.config.EnableBlockIP {
			return fmt.Errorf("IP blocking is disabled")
		}
		fn, err = h.blockIP(action.Target)
	case "terminate_process":
		if !h.config.EnableProcessKill {
			return fmt.Errorf("process termination is disabled")
		}
		fn, err = h.terminateProcess(action.Target)
	default:
		return fmt.Errorf("unsupported action type: %s", action.Type)
	}

	if err != nil {
		return fmt.Errorf("failed to execute action: %v", err)
	}

	// Store the action for potential rollback
	actionKey := fmt.Sprintf("%s:%s", action.Type, action.Target)
	h.actions[actionKey] = &Action{
		Type:       action.Type,
		Target:     action.Target,
		StartTime:  time.Now(),
		ExpiryTime: time.Now().Add(h.config.RollbackTimeout),
		Success:    true,
		RollbackFn: fn,
	}

	return nil
}

// logAction logs a prevention action to Elasticsearch
func (h *Handler) logAction(action ml.PreventionAction) error {
	return h.esLogger.LogPreventionAction(elasticsearch.PreventionAction{
		Type:      action.Type,
		Target:    action.Target,
		Timestamp: action.Timestamp,
		Reason:    action.Reason,
		Success:   true,
		Metadata: map[string]interface{}{
			"confidence": action.Confidence,
		},
	})
}

// isWhitelisted checks if the target is in the whitelist
func (h *Handler) isWhitelisted(action ml.PreventionAction) bool {
	switch action.Type {
	case "block_ip":
		for _, ip := range h.config.WhitelistedIPs {
			if ip == action.Target {
				return true
			}
		}
	case "terminate_process":
		for _, proc := range h.config.WhitelistedProcs {
			if proc == action.Target {
				return true
			}
		}
	}
	return false
}

// cleanupExpiredActions periodically checks for and rolls back expired actions
func (h *Handler) cleanupExpiredActions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			h.mu.Lock()
			now := time.Now()
			for key, action := range h.actions {
				if now.After(action.ExpiryTime) && !action.RolledBack {
					if err := action.RollbackFn(); err != nil {
						log.Printf("Warning: failed to rollback action %s: %v", key, err)
					} else {
						action.RolledBack = true
						delete(h.actions, key)
					}
				}
			}
			h.mu.Unlock()
		}
	}
}

// rollbackAllActions rolls back all active prevention actions
func (h *Handler) rollbackAllActions() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for key, action := range h.actions {
		if !action.RolledBack {
			if err := action.RollbackFn(); err != nil {
				log.Printf("Warning: failed to rollback action %s during shutdown: %v", key, err)
			}
		}
	}
}

// blockIP implements IP blocking, returns rollback function
func (h *Handler) blockIP(ip string) (func() error, error) {
	if h.config.DryRun {
		log.Printf("[DryRun] Would block IP: %s", ip)
		return func() error { return nil }, nil
	}

	// TODO: Implement actual IP blocking using platform-specific mechanisms
	log.Printf("Blocking IP: %s", ip)

	return func() error {
		log.Printf("Unblocking IP: %s", ip)
		return nil
	}, nil
}

// terminateProcess implements process termination, returns rollback function
func (h *Handler) terminateProcess(pid string) (func() error, error) {
	if h.config.DryRun {
		log.Printf("[DryRun] Would terminate process: %s", pid)
		return func() error { return nil }, nil
	}

	// TODO: Implement actual process termination using platform-specific mechanisms
	log.Printf("Terminating process: %s", pid)

	return func() error {
		log.Printf("Process %s terminated (no rollback possible)", pid)
		return nil
	}, nil
}
