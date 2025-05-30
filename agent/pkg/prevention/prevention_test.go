package prevention

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// testPreventionLayer extends PreventionLayer for testing
type testPreventionLayer struct {
	*PreventionLayer
	criticalProcesses map[string]bool
}

// newTestPreventionLayer creates a new test prevention layer
func newTestPreventionLayer(dryRun bool) *testPreventionLayer {
	return &testPreventionLayer{
		PreventionLayer:   NewPreventionLayer(dryRun),
		criticalProcesses: make(map[string]bool),
	}
}

// isCriticalProcess overrides the base method for testing
func (p *testPreventionLayer) isCriticalProcess(name string) bool {
	return p.criticalProcesses[name]
}

func TestPreventionLayer_BlockIP(t *testing.T) {
	// Test in dry-run mode
	layer := NewPreventionLayer(true)

	// Test blocking IP
	action, err := layer.BlockIP("192.168.1.100", "test block")
	assert.NoError(t, err)
	assert.NotNil(t, action)
	assert.Equal(t, "block_ip", action.Type)
	assert.Equal(t, "192.168.1.100", action.Target)
	assert.True(t, action.Success)
	assert.False(t, action.RolledBack)

	// Test whitelisted IP
	layer.AddToWhitelist("192.168.1.200")
	_, err = layer.BlockIP("192.168.1.200", "test block")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "whitelisted")
}

func TestPreventionLayer_TerminateProcess(t *testing.T) {
	// Test in dry-run mode
	layer := newTestPreventionLayer(true)

	// Test terminating process
	action, err := layer.TerminateProcess(1234, "test termination")
	assert.NoError(t, err)
	assert.NotNil(t, action)
	assert.Equal(t, "terminate_process", action.Type)
	assert.Equal(t, "1234", action.Target)
	assert.True(t, action.Success)
	assert.False(t, action.RolledBack)

	// Test critical process
	layer.criticalProcesses["system"] = true
	_, err = layer.TerminateProcess(5678, "test termination")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "critical process")
}

func TestPreventionLayer_RollbackAction(t *testing.T) {
	// Test in dry-run mode
	layer := NewPreventionLayer(true)

	// Test rollback of IP block
	action := Action{
		Type:      "block_ip",
		Target:    "192.168.1.100",
		Reason:    "test block",
		Timestamp: time.Now(),
		Success:   true,
	}

	err := layer.RollbackAction(action)
	assert.NoError(t, err)
	assert.True(t, action.RolledBack)

	// Test rollback of process termination (should fail)
	action = Action{
		Type:      "terminate_process",
		Target:    "1234",
		Reason:    "test termination",
		Timestamp: time.Now(),
		Success:   true,
	}

	err = layer.RollbackAction(action)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be rolled back")
}

func TestPreventionLayer_Whitelist(t *testing.T) {
	layer := NewPreventionLayer(true)

	// Test adding to whitelist
	layer.AddToWhitelist("192.168.1.100")
	assert.True(t, layer.whitelist["192.168.1.100"])

	// Test removing from whitelist
	layer.RemoveFromWhitelist("192.168.1.100")
	assert.False(t, layer.whitelist["192.168.1.100"])
}

func TestPreventionLayer_GetActions(t *testing.T) {
	layer := NewPreventionLayer(true)

	// Add some actions
	layer.BlockIP("192.168.1.100", "test block 1")
	layer.BlockIP("192.168.1.101", "test block 2")

	// Get actions
	actions := layer.GetActions()
	assert.Len(t, actions, 2)
	assert.Equal(t, "192.168.1.100", actions[0].Target)
	assert.Equal(t, "192.168.1.101", actions[1].Target)
} 