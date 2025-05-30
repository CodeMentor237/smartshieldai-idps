package prevention

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// Action represents a prevention action
type Action struct {
	Type        string                 `json:"type"`
	Target      string                 `json:"target"`
	Reason      string                 `json:"reason"`
	Timestamp   time.Time             `json:"timestamp"`
	Context     map[string]interface{} `json:"context"`
	Success     bool                  `json:"success"`
	Error       string                `json:"error,omitempty"`
	RolledBack  bool                  `json:"rolled_back"`
	RollbackErr string                `json:"rollback_error,omitempty"`
}

// PreventionLayer handles system-level prevention actions
type PreventionLayer struct {
	dryRun     bool
	whitelist  map[string]bool
	actions    []Action
	rollbackFn func(Action) error
}

// NewPreventionLayer creates a new prevention layer
func NewPreventionLayer(dryRun bool) *PreventionLayer {
	return &PreventionLayer{
		dryRun:    dryRun,
		whitelist: make(map[string]bool),
		actions:   make([]Action, 0),
	}
}

// BlockIP blocks an IP address using the appropriate firewall
func (p *PreventionLayer) BlockIP(ip string, reason string) (*Action, error) {
	// Check whitelist
	if p.whitelist[ip] {
		return nil, fmt.Errorf("IP %s is whitelisted", ip)
	}

	action := Action{
		Type:      "block_ip",
		Target:    ip,
		Reason:    reason,
		Timestamp: time.Now(),
		Context: map[string]interface{}{
			"os": runtime.GOOS,
		},
	}

	if p.dryRun {
		action.Success = true
		p.actions = append(p.actions, action)
		return &action, nil
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	case "windows":
		cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name=BlockIP", "dir=in", "action=block", "remoteip="+ip)
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	if err := cmd.Run(); err != nil {
		action.Success = false
		action.Error = err.Error()
		p.actions = append(p.actions, action)
		return &action, fmt.Errorf("failed to block IP: %v", err)
	}

	action.Success = true
	p.actions = append(p.actions, action)
	return &action, nil
}

// TerminateProcess terminates a process by PID
func (p *PreventionLayer) TerminateProcess(pid int32, reason string) (*Action, error) {
	action := Action{
		Type:      "terminate_process",
		Target:    fmt.Sprintf("%d", pid),
		Reason:    reason,
		Timestamp: time.Now(),
		Context: map[string]interface{}{
			"os": runtime.GOOS,
		},
	}

	// Get process info
	proc, err := process.NewProcess(pid)
	if err != nil {
		action.Success = false
		action.Error = err.Error()
		p.actions = append(p.actions, action)
		return &action, fmt.Errorf("failed to get process info: %v", err)
	}

	// Check if process is critical
	name, err := proc.Name()
	if err != nil {
		name = "unknown"
	}
	if p.isCriticalProcess(name) {
		return nil, fmt.Errorf("cannot terminate critical process: %s", name)
	}

	if p.dryRun {
		action.Success = true
		p.actions = append(p.actions, action)
		return &action, nil
	}

	// Terminate process
	if err := proc.Terminate(); err != nil {
		action.Success = false
		action.Error = err.Error()
		p.actions = append(p.actions, action)
		return &action, fmt.Errorf("failed to terminate process: %v", err)
	}

	action.Success = true
	p.actions = append(p.actions, action)
	return &action, nil
}

// RollbackAction attempts to rollback a prevention action
func (p *PreventionLayer) RollbackAction(action Action) error {
	if p.dryRun {
		return nil
	}

	switch action.Type {
	case "block_ip":
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "linux":
			cmd = exec.Command("iptables", "-D", "INPUT", "-s", action.Target, "-j", "DROP")
		case "windows":
			cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
				"name=BlockIP", "remoteip="+action.Target)
		default:
			return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}

		if err := cmd.Run(); err != nil {
			action.RolledBack = false
			action.RollbackErr = err.Error()
			return fmt.Errorf("failed to rollback IP block: %v", err)
		}

	case "terminate_process":
		// Process termination cannot be rolled back
		return fmt.Errorf("process termination cannot be rolled back")
	}

	action.RolledBack = true
	return nil
}

// AddToWhitelist adds an IP or process to the whitelist
func (p *PreventionLayer) AddToWhitelist(target string) {
	p.whitelist[target] = true
}

// RemoveFromWhitelist removes an IP or process from the whitelist
func (p *PreventionLayer) RemoveFromWhitelist(target string) {
	delete(p.whitelist, target)
}

// GetActions returns all prevention actions
func (p *PreventionLayer) GetActions() []Action {
	return p.actions
}

// isCriticalProcess checks if a process is critical and should not be terminated
func (p *PreventionLayer) isCriticalProcess(name string) bool {
	criticalProcesses := map[string]bool{
		"system":     true,
		"init":       true,
		"systemd":    true,
		"svchost":    true,
		"lsass":      true,
		"csrss":      true,
		"wininit":    true,
		"services":   true,
		"smss":       true,
		"winlogon":   true,
		"spoolsv":    true,
		"explorer":   true,
		"taskmgr":    true,
		"cmd":        true,
		"powershell": true,
	}

	return criticalProcesses[strings.ToLower(name)]
} 