package rules

import (
	"log"
	"time"
)

// UpdateService handles periodic rule updates
type UpdateService struct {
	manager      *RulesManager
	checkInterval time.Duration
	stopChan     chan struct{}
}

// NewUpdateService creates a new rule update service
func NewUpdateService(manager *RulesManager, checkInterval time.Duration) *UpdateService {
	return &UpdateService{
		manager:      manager,
		checkInterval: checkInterval,
		stopChan:     make(chan struct{}),
	}
}

// Start begins periodic rule update checks
func (us *UpdateService) Start() {
	ticker := time.NewTicker(us.checkInterval)
	go func() {
		for {
			select {
			case <-ticker.C:
				us.checkAndUpdate()
			case <-us.stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}

// Stop halts periodic rule update checks
func (us *UpdateService) Stop() {
	close(us.stopChan)
}

// checkAndUpdate checks for and applies rule updates
func (us *UpdateService) checkAndUpdate() {
	updated, err := us.manager.CheckForUpdates()
	if err != nil {
		log.Printf("Error checking for rule updates: %v", err)
		return
	}

	if updated {
		log.Println("New rule updates found, applying updates...")
		if err := us.manager.UpdateRules(); err != nil {
			log.Printf("Error updating rules: %v", err)
			return
		}
		log.Println("Rules successfully updated")
	}
}